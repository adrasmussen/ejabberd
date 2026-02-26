-module(ejabberd_krb_init).

-author('alex@nonlocal.cloud').

-behaviour(p1_fsm).

-include("logger.hrl").
-export([
    start_link/2,
    init/1,
    ready/3,
    gss_continue/3,
    sasl_final/3,
    handle_event/3,
    handle_sync_event/4,
    handle_info/3,
    code_change/4,
    terminate/3
]).

-type mode() :: gssapi | sasl.

-record(?MODULE, {
    mode :: mode(),
    realm :: krb_realm:realm(),
    ticket :: krb_proto:ticket(),
    gss_context = none :: gss_mechanism:state() | none
}).

% this could be extended to have per-call or per-host creds
% (and in fact that flexibily is why we use a dedicated krb5
% library instead of a libgssapi wrapper), but for a first
% pass we just use configured defaults
%
% additionally, we assume the following:
%  * caller is either using TLS or doesn't care about channel
%    security (i.e. we don't expose wrap)
%  * targets are provided as svc@fqdn
%  * mutual auth is only needed for SASL
-spec start_link(binary(), mode()) -> pid().
start_link(Target, Mode) ->
    Reg_name = misc:binary_to_atom(
        list_to_binary([<<"krb_init_">>, erlang:ref_to_list(make_ref())])
    ),
    p1_fsm:start_link({local, Reg_name}, ?MODULE, [Target, Mode], []).

init([Target, Mode]) ->
    % the krb_sup should have already been started
    {ok, Realm} = krb_realm:open("NONLOCAL.CLOUD"),

    % if we wanted to search the keytab for a specific
    % principal, we would do so here
    {ok, [KeyTab | _]} = krb_mit_keytab:file("/etc/client.keytab"),
    #{principal := Principal, key := Key} = KeyTab,

    {ok, TGT} = krb_realm:authenticate_keytab(Realm, Principal, Key),

    % there are other representations but we are bypassing libgssapi
    % and the NT host service is unambiguous for a single realm
    [TargetService, TargetHost] = string:split(Target, "@"),

    {ok, Ticket} = krb_realm:obtain_ticket(Realm, TGT, [TargetService, TargetHost]),

    % even though kerberos gssapi mech goes first, we don't have an
    % easy way to get the caller's pid in here
    {ok, ready, #?MODULE{mode = Mode, realm = Realm, ticket = Ticket, gss_context = none}}.

ready(start, From, S) ->
    % initiate can also return {ok, Ctx} and {error, _}, which
    % we shamelessly make the caller's problem
    case
        {
            S#?MODULE.mode,
            gss_krb5:initiate(#{
                chan_bindings => <<0:128>>,
                mutual_auth => S#?MODULE.mode == sasl,
                sequence => true,
                ticket => S#?MODULE.ticket
            })
        }
    of
        {_, {continue, Token, Context}} ->
            {reply, {ok, Token}, gss_continue, S#?MODULE{gss_context = Context}};
        {gss, {ok, Token, _Context}} ->
            % unfortunately, there is no {stop, Reply, ...} in p1_fsm
            p1_fsm:reply(From, {ok, Token}),
            {stop, normal, {}}
    end.

gss_continue(Token, From, S) ->
    % as above, so below
    case {S#?MODULE.mode, gss_krb5:continue(Token, S#?MODULE.gss_context)} of
        {gss, {continue, NewToken, Context}} ->
            {reply, {ok, NewToken}, gss_continue, S#?MODULE{gss_context = Context}};
        {gss, {ok, _Context}} ->
            p1_fsm:reply(From, ok),
            {stop, normal, {}};
        % the empty reply is part of the sasl mechanism, and should
        % be sent like any other token during the exchange
        {sasl, {ok, Context}} ->
            {reply, {ok, <<>>}, sasl_final, S#?MODULE{gss_context = Context}}
    end.

sasl_final(Token, From, S) ->
    % strictly speaking, we should be checking the contents of the
    % unwrapped token, but we are only using kerberos for auth
    {ok, <<_Layer:8, _MaxBuf:24>>, Context} = gss_krb5:unwrap(Token, S#?MODULE.gss_context),

    % 1:8 specifies "no required sasl layers"
    % 0:24 disables buffering
    {ok, NewToken, _Context} = gss_krb5:wrap(<<1:8, 0:24>>, Context),

    p1_fsm:reply(From, {ok, NewToken}),
    {stop, normal, {}}.

% for now (no persistent tgt/ap state), we ignore any of the all-state
% events as they don't impact the context setup
handle_event(close, _StateName, S) ->
    {stop, normal, S};
handle_event(_Event, StateName, S) ->
    {next_state, StateName, S}.

handle_sync_event(_Event, _From, StateName, S) ->
    {reply, {StateName, S}, StateName, S}.

handle_info(Info, StateName, S) ->
    ?DEBUG(
        "Unexpected Info: ~p~nIn state: "
        "~p~n when StateData is: ~p",
        [Info, StateName, S]
    ),
    {next_state, StateName, S}.

terminate(_Reason, _StateName, _StatData) -> ok.

code_change(_OldVsn, StateName, S, _Extra) ->
    {ok, StateName, S}.
