using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using TGuard.App.Services;
using TGuard.Core.Online;

namespace TGuard.App.Views;

public partial class ChatView : UserControl, IRefreshable
{
    private readonly ObservableCollection<ChatRow> _rows = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(5) };
    private long _lastId;
    private bool _active;
    private bool _busy;
    private bool _prefilled;

    public ChatView()
    {
        InitializeComponent();
        Messages.ItemsSource = _rows;
        _timer.Tick += async (_, _) => await PollAsync();
    }

    public async Task RefreshAsync()
    {
        _timer.Start();
        await PollAsync();
    }

    private async Task PollAsync()
    {
        if (_busy || (!_active && !IsVisible)) return;
        _busy = true;
        try
        {
            if (!App.Backend.ServiceAvailable || App.Backend.Showcase is not null)
            {
                ShowOnline(false);
                ShowStart(offline: true);
                return;
            }
            var state = await App.Backend.ChatStateAsync(_lastId);
            Apply(state);
        }
        catch (Exception)
        {
            ShowOnline(false);
            if (!_active) ShowStart(offline: true);
        }
        finally { _busy = false; }
    }

    private void Apply(ChatState state)
    {
        if (!_prefilled)
        {
            NameBox.Text = state.Name ?? Environment.UserName;
            EmailBox.Text = state.Email ?? "";
            _prefilled = true;
        }
        ShowOnline(state.Online);
        if (!state.Active)
        {
            if (_active) ResetConversation();
            ShowStart(offline: !state.Online);
            return;
        }

        _active = true;
        StartCard.Visibility = Visibility.Collapsed;
        ChatCard.Visibility = Visibility.Visible;
        RemoteButton.Visibility = Visibility.Visible;
        var closed = state.Status == "closed";
        ChatTitle.Text = state.Agent is { Length: > 0 } agent ? S.F("help.with", agent) : S.T("help.waiting");
        ChatSub.Text = closed ? S.T("help.closed") : S.T("help.open");
        Input.IsEnabled = SendButton.IsEnabled = RemoteButton.IsEnabled = !closed;
        NewChatButton.Visibility = closed ? Visibility.Visible : Visibility.Collapsed;
        Add(state.Messages);
    }

    private void Add(System.Collections.Generic.IEnumerable<ChatMessage> messages)
    {
        var added = false;
        foreach (var m in messages.Where(m => m.Id > _lastId).OrderBy(m => m.Id))
        {
            _rows.Add(new ChatRow(m));
            _lastId = m.Id;
            added = true;
            if (m.FromAdmin && !IsVisible) App.Current.NotifyChat(m.AdminName, m.Body);
        }
        if (added) MessagesScroll.ScrollToEnd();
    }

    private void ShowStart(bool offline)
    {
        StartCard.Visibility = Visibility.Visible;
        ChatCard.Visibility = Visibility.Collapsed;
        RemoteButton.Visibility = Visibility.Collapsed;
        StartForm.Visibility = offline ? Visibility.Collapsed : Visibility.Visible;
        OfflinePanel.Visibility = offline ? Visibility.Visible : Visibility.Collapsed;
        StartNote.Text = offline ? S.T("help.offline") : S.T("help.start.note");
    }

    private void ShowOnline(bool online)
    {
        OnlineText.Text = online ? S.T("help.online") : S.T("help.offline.short");
        OnlinePill.Background = Palette.B(online ? "GoodSoft" : "Line");
        OnlineText.Foreground = Palette.B(online ? "Good" : "Muted");
    }

    private void ResetConversation()
    {
        _active = false;
        _rows.Clear();
        _lastId = 0;
    }

    private async Task StartAsync(bool remote)
    {
        StartError.Visibility = Visibility.Collapsed;
        var body = FirstMessage.Text.Trim();
        if (body.Length == 0)
        {
            if (!remote) { ShowError(S.T("help.empty")); return; }
            body = S.T("help.remote.default");
        }
        StartButton.IsEnabled = StartRemoteButton.IsEnabled = false;
        try
        {
            var state = await App.Backend.StartChatAsync(NameBox.Text.Trim(), EmailBox.Text.Trim(), body, remote);
            if (state.Error is { } error)
            {
                ShowError(error == "already_open" ? S.T("help.already") : S.T("help.offline"));
                return;
            }
            FirstMessage.Text = "";
            Apply(state);
        }
        catch (Exception ex) { ShowError(QuarantineView.Friendly(ex)); }
        finally { StartButton.IsEnabled = StartRemoteButton.IsEnabled = true; }
    }

    private void ShowError(string text)
    {
        StartError.Text = text;
        StartError.Visibility = Visibility.Visible;
    }

    private async Task SendAsync(string text, bool remote)
    {
        if (text.Length == 0) return;
        SendButton.IsEnabled = false;
        try
        {
            var message = await App.Backend.SendChatAsync(text, remote);
            if (message is null)
            {
                ChatSub.Text = S.T("help.closed");
                NewChatButton.Visibility = Visibility.Visible;
                return;
            }
            Add(new[] { message });
            if (!remote) Input.Text = "";
        }
        catch (Exception ex) { Dialog.Alert(S.T("error"), QuarantineView.Friendly(ex), DialogKind.Danger); }
        finally { SendButton.IsEnabled = true; }
    }

    private async void Start_Click(object sender, RoutedEventArgs e) => await StartAsync(false);

    private async void StartRemote_Click(object sender, RoutedEventArgs e) => await StartAsync(true);

    private async void Send_Click(object sender, RoutedEventArgs e) => await SendAsync(Input.Text.Trim(), false);

    private async void Input_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        e.Handled = true;
        await SendAsync(Input.Text.Trim(), false);
    }

    private async void Remote_Click(object sender, RoutedEventArgs e)
    {
        if (!Dialog.Confirm(S.T("help.remote.title"), S.T("help.remote.confirm"), S.T("help.remote"), DialogKind.Info)) return;
        await SendAsync(Input.Text.Trim() is { Length: > 0 } t ? t : S.T("help.remote.default"), true);
        Input.Text = "";
    }

    private async void NewChat_Click(object sender, RoutedEventArgs e)
    {
        try { await App.Backend.ResetChatAsync(); } catch (Exception) { }
        ResetConversation();
        await PollAsync();
    }

    private void QuickAssist_Click(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo("ms-quick-assist:") { UseShellExecute = true }); }
        catch (Exception)
        {
            try { Process.Start(new ProcessStartInfo("quickassist.exe") { UseShellExecute = true }); }
            catch (Exception) { Dialog.Alert(S.T("help.remote.title"), S.T("help.quickassist.missing"), DialogKind.Warning); }
        }
    }

    private async void Ticket_Click(object sender, RoutedEventArgs e)
    {
        var settings = await App.Backend.GetSettingsAsync();
        try { Process.Start(new ProcessStartInfo(SiteClient.HelpUrl(settings)) { UseShellExecute = true }); }
        catch (Exception) { }
    }
}

public sealed class ChatRow
{
    public ChatRow(ChatMessage m)
    {
        Body = string.IsNullOrEmpty(m.AttachmentName) ? m.Body : $"{m.Body}\n[{m.AttachmentName}]".Trim();
        Align = m.FromAdmin ? HorizontalAlignment.Left : HorizontalAlignment.Right;
        Background = Palette.B(m.FromAdmin ? "RoyalSoft" : "Royal");
        Foreground = m.FromAdmin ? Palette.B("Ink") : Brushes.White;
        var when = m.CreatedAt?.ToLocalTime().ToString("HH:mm") ?? "";
        Meta = m.FromAdmin ? $"{m.AdminName ?? "luis-tavares.pt"} · {when}" : when;
    }

    public string Body { get; }
    public HorizontalAlignment Align { get; }
    public Brush Background { get; }
    public Brush Foreground { get; }
    public string Meta { get; }
}
