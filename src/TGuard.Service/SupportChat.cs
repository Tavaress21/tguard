using TGuard.Core.Online;

namespace TGuard.Service;

public sealed class SupportChat
{
    private readonly ServiceState _state;

    public SupportChat(ServiceState state) => _state = state;

    public async Task<ChatState> StateAsync(long afterId, CancellationToken ct = default)
    {
        var st = _state.State;
        var client = new SiteClient(_state.Settings);
        var result = new ChatState { Name = st.AccountName, Email = st.AccountEmail };
        if (st.ChatId is long id && !string.IsNullOrEmpty(st.ChatToken))
        {
            var update = await client.ChatMessagesAsync(id, st.ChatToken, afterId, ct);
            if (update.Status == "gone") Reset();
            else
            {
                result.Active = true;
                result.Online = true;
                result.Status = update.Status;
                result.Agent = update.Agent;
                result.Messages = update.Messages;
                return result;
            }
        }
        result.Online = await client.ChatOnlineAsync(ct);
        return result;
    }

    public async Task<ChatState> StartAsync(string name, string? email, string body, bool remote, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(body)) throw new ArgumentException("empty message");
        var st = _state.State;
        var start = await new SiteClient(_state.Settings).StartChatAsync(st.EnsureInstallId(), st.AccountToken,
            string.IsNullOrWhiteSpace(name) ? Environment.UserName : name.Trim(), email, body.Trim(), remote, ct);
        if (start.Error is not null) return new ChatState { Error = start.Error, Name = st.AccountName, Email = st.AccountEmail };

        st.ChatId = start.ConversationId;
        st.ChatToken = start.AccessToken;
        st.Save();
        return new ChatState { Online = true, Active = true, Status = "open", Messages = start.Messages, Name = st.AccountName, Email = st.AccountEmail };
    }

    public async Task<ChatMessage?> SendAsync(string body, bool remote, CancellationToken ct = default)
    {
        var st = _state.State;
        if (st.ChatId is not long id || string.IsNullOrEmpty(st.ChatToken)) throw new InvalidOperationException("no conversation");
        if (string.IsNullOrWhiteSpace(body)) throw new ArgumentException("empty message");
        return await new SiteClient(_state.Settings).SendChatAsync(id, st.ChatToken, st.EnsureInstallId(), body.Trim(), remote, ct);
    }

    public void Reset()
    {
        var st = _state.State;
        st.ChatId = null;
        st.ChatToken = null;
        st.Save();
    }
}
