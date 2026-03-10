-module(ejabberd_krb_cache).

-author('alex@nonlocal.cloud').

-behaviour(gen_server).
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    code_change/3,
    terminate/2
]).

-include("logger.hrl").
-export([start_link/0, local_creds/1, remote_creds/1]).

-record(?MODULE, {
    realm :: krb_realm:realm(),
    server_keytab :: [krb_mit_keytab:keytab_entry()],
    client_keytab :: krb_mit_keytab:keytab_entry(),
    tgt = none :: krb_proto:ticket() | none,
    creds = #{} :: map()
}).

% TODO -- reload keytabs on reconfigure

%
% public API
%
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

remote_creds(Target) ->
    gen_server:call(?MODULE, {ap_req, Target}).

local_creds(Ticket) ->
    gen_server:call(?MODULE, {ap_resp, Ticket}).

%
% internal
%
fetch_creds(Target, #?MODULE{creds = Creds} = S0) ->
    {ok, TGT, S1} = fetch_tgt(S0),
    [TargetService, TargetHost] = string:split(Target, "@"),
    {ok, Ticket} = krb_realm:obtain_ticket(S1#?MODULE.realm, TGT, [TargetService, TargetHost]),
    {ok, Ticket, S1#?MODULE{creds = maps:put(Target, Ticket, Creds)}}.

fetch_tgt(#?MODULE{tgt = TGT} = S) ->
    case ticket_valid(TGT) of
        false ->
            #{principal := Principal, key := Key} = S#?MODULE.client_keytab,
            {ok, NewTGT} = krb_realm:authenticate_keytab(S#?MODULE.realm, Principal, Key),
            {ok, NewTGT, S#?MODULE{tgt = NewTGT}};
        true ->
            {ok, TGT, S}
    end.

ticket_valid(Ticket) ->
    case Ticket of
        none ->
            false;
        Ticket ->
            EndKrbTime = maps:get(endtime, Ticket),
            SysKrbTime = krb_proto:system_time_to_krbtime(erlang:system_time(second) + 30, second),
            EndKrbTime > SysKrbTime
    end.

%
% gen_server API
%
init([]) ->
    % the krb_sup should have already been started by elixir
    {ok, Realm} = krb_realm:open("NONLOCAL.CLOUD"),

    % read in all server keytabs, since we will filter the list
    % based on ability to decrypt incoming ticket
    {ok, SKeyTab} = krb_mit_keytab:file("/etc/krb5.keytab"),

    % for the moment, only pull in the first client key
    {ok, [CKeyTab | _]} = krb_mit_keytab:file("/etc/client.keytab"),

    {ok, #?MODULE{realm = Realm, server_keytab = SKeyTab, client_keytab = CKeyTab}}.

handle_call({ap_req, Target}, _From, #?MODULE{creds = Creds} = S0) ->
    Ticket = maps:get(Target, Creds, none),
    case ticket_valid(Ticket) of
        false ->
            {ok, NewTicket, S1} = fetch_creds(Target, S0),
            {reply, {ok, NewTicket}, S1};
        true ->
            {reply, {ok, Ticket}, S0}
    end;
handle_call({ap_resp, Ticket}, _From, #?MODULE{server_keytab = KeyTab} = S0) ->
    {ok, Matches} = krb_mit_keytab:filter_for_ticket(KeyTab, Ticket),
    {reply, {ok, Matches}, S0}.

handle_cast(_Event, State) -> {noreply, State}.

handle_info(_Info, State) -> {noreply, State}.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

terminate(_Reason, _State) -> {}.
