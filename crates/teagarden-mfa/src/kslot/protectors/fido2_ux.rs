//! Operator-facing text and plumbing for the FIDO2 protector: touch announcements,
//! the PIN prompt, and plain-language failure descriptions.
//!
//! Everything the operator must see is written to `/dev/tty` and falls back to
//! stderr when there is no controlling terminal, so redirecting either stream
//! cannot hide a touch prompt.
//!
//! The strings matched here are the ones `age-plugin-fido2-hmac` v0.5.0 and its
//! `go-libfido2` dependency emit; the tests below quote the source file each came
//! from.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use super::fido2_mode::Fido2Mode;

/// The plugin's touch notice (`LoadSecret` and `NewCredentials`): the full text is
/// `Please touch your token...`, sometimes with a trailing newline.
const TOUCH_TEXT: &str = "Please touch your token";
/// `FindDevice` when several keys are attached: `Found %d devices. Please touch the
/// one you want to use.` (no trailing newline).
const SELECT_HEAD: &str = "Found ";
const SELECT_TAIL: &str = " devices. Please touch the one you want to use.";

/// A touch-related message from `age-plugin-fido2-hmac`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Notice {
    /// `Please touch your token...`
    Touch,
    /// `Found N devices. Please touch the one you want to use.`
    SelectDevice(u32),
}

/// Parse `Found <digits> devices. Please touch the one you want to use.` at the
/// start of `text`; `Some((length, devices))` when it is complete.
fn parse_select(text: &str) -> Option<(usize, u32)> {
    let rest = text.strip_prefix(SELECT_HEAD)?;
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let devices = rest[..digits].parse().ok()?;
    rest[digits..]
        .starts_with(SELECT_TAIL)
        .then_some((SELECT_HEAD.len() + digits + SELECT_TAIL.len(), devices))
}

/// Find the first plugin touch notice in `text`: `(start, end, notice)`.
pub(super) fn find_notice(text: &str) -> Option<(usize, usize, Notice)> {
    let touch = text.find(TOUCH_TEXT).map(|start| {
        // The plugin appends `...`.
        let dots = text[start + TOUCH_TEXT.len()..]
            .bytes()
            .take_while(|b| *b == b'.')
            .count();
        (start, start + TOUCH_TEXT.len() + dots, Notice::Touch)
    });
    let select = text.match_indices(SELECT_HEAD).find_map(|(start, _)| {
        parse_select(&text[start..])
            .map(|(len, devices)| (start, start + len, Notice::SelectDevice(devices)))
    });
    match (touch, select) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, b) => a.or(b),
    }
}

/// Classify one whole `display_message` string.
pub(super) fn classify_notice(message: &str) -> Option<Notice> {
    find_notice(message).map(|(_, _, notice)| notice)
}

/// The PIN prompt shown on the terminal for a plugin PIN request: a banner line,
/// so a PIN entry is announced as plainly as a touch, then the input prompt.
///
/// The plugin's own text is `Please enter you PIN:` on the unwrap path (a typo) and
/// `Please enter your PIN:` elsewhere. Replace both with one fixed prompt.
pub(super) fn pin_prompt(description: &str) -> String {
    if description.to_ascii_lowercase().contains("pin") {
        ">>> Enter the PIN of your security key now <<<\n  PIN: ".to_string()
    } else {
        format!("  {}: ", description.trim_end_matches(':').trim())
    }
}

/// The numbered banner printed before a touch.
pub(super) fn touch_banner(n: usize, total: usize, purpose: &str) -> String {
    if n > total {
        format!(">>> Touch your security key now (touch {n}: {purpose}) <<<")
    } else {
        format!(">>> Touch your security key now (touch {n} of {total}: {purpose}) <<<")
    }
}

/// The banner printed when the plugin asks the operator to pick one of several keys.
pub(super) fn select_banner(devices: u32) -> String {
    format!(
        ">>> {devices} security keys are attached. Touch the one you want to use now \
         (an extra touch that is not numbered; set FIDO2_TOKEN to a device path from \
         `fido2-token -L` to skip it) <<<"
    )
}

/// Printed after a touch succeeded.
pub(super) const CONFIRMED: &str = "  ✓ key confirmed";

/// The touches an enrollment costs, in order, in every available mode: the plugin
/// creates the credential (touch 1), then derives the key from it (touch 2).
/// Post-quantum mode costs the same two.
const ENROLL_TOUCHES: [&str; 2] = ["creating the credential", "deriving the key"];

/// What is printed before an enrollment starts: the mode, and the exact sequence
/// of PIN entries and touches it will ask for.
fn enrollment_preamble(mode: Fido2Mode) -> String {
    let [first, second] = ENROLL_TOUCHES;
    let (unlock, pin_step, note) = if mode.requires_pin() {
        (
            "the key's PIN and a touch",
            "the key's PIN",
            "The PIN is asked once. If the key has no PIN set, enrollment stops and the slot \
             is not saved.",
        )
    } else {
        (
            "a touch and no PIN",
            "the key's PIN, only if the key has one (to create the credential; unlocking \
             never asks for it)",
            "A key set to always verify its user (alwaysUv) also checks your fingerprint on \
             each touch.",
        )
    };
    format!(
        "FIDO2 enrollment, mode {}: unlocking this slot will need {unlock}.\n\
         This enrollment asks for, in order:\n  \
         1. {pin_step}\n  \
         2. touch 1 of 2 ({first})\n  \
         3. touch 2 of 2 ({second})\n\
         {note}",
        mode.title()
    )
}

/// What is printed before an unlock: the slot's recorded mode and its sequence.
fn unlock_notice(mode: Fido2Mode, volume: Option<&str>) -> String {
    let what = match volume {
        Some(name) => format!("'{name}'"),
        None => "the volume".to_string(),
    };
    let steps = if mode.requires_pin() {
        "enter the key's PIN, then touch the key."
    } else {
        "touch the key. No PIN is asked."
    };
    format!(
        "Unlocking {what} with FIDO2 (mode {}): {steps}",
        mode.title()
    )
}

/// What the operator will be asked for, in order.
pub(super) struct TouchPlan {
    pub(super) preamble: String,
    pub(super) purposes: Vec<String>,
}

impl TouchPlan {
    /// Enrolling a new credential in `mode`.
    pub(super) fn enrollment(mode: Fido2Mode) -> Self {
        Self {
            preamble: enrollment_preamble(mode),
            purposes: ENROLL_TOUCHES.iter().map(|p| p.to_string()).collect(),
        }
    }

    /// Unlocking one slot recorded in `mode`: one touch.
    pub(super) fn unlock(mode: Fido2Mode, volume: Option<&str>) -> Self {
        Self {
            preamble: unlock_notice(mode, volume),
            purposes: vec!["unlocking the volume".to_string()],
        }
    }
}

/// Why a FIDO2 operation failed, as far as the plugin's text tells.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    WrongPin,
    PinBlocked,
    PinRequired,
    NoDevice,
    TouchTimeout,
    WrongKey,
    PluginMissing,
    PluginOld,
    Denied,
    UvRequired,
    Other,
}

/// Classify plugin or age failure text. Matching is on lower-cased substrings of
/// the real messages; order matters where one contains another.
pub(super) fn classify_failure(text: &str) -> Failure {
    let t = text.to_ascii_lowercase();
    let has = |needle: &str| t.contains(needle);
    if has("pin auth blocked") {
        Failure::PinBlocked
    } else if has("pin invalid") {
        Failure::WrongPin
    } else if has("pin required") {
        Failure::PinRequired
    } else if has("timed out waiting for device") {
        Failure::NoDevice
    } else if has("action timed out") || has("timeout reached before any device was touched") {
        Failure::TouchTimeout
    } else if has("no matching keys") || has("no credentials") {
        Failure::WrongKey
    } else if has("operation denied") {
        Failure::Denied
    } else if has("libfido2 error 54") {
        // CTAP2_ERR_PUAT_REQUIRED, which go-libfido2 does not name.
        Failure::UvRequired
    } else if has("is incompatible") {
        Failure::PluginOld
    } else if has("not found on path") || has("on the path") {
        Failure::PluginMissing
    } else {
        Failure::Other
    }
}

/// A plain-language explanation of a failure. Unrecognised text is passed through
/// so nothing is hidden. Plugin messages never contain the PIN.
pub(super) fn describe_failure(text: &str) -> String {
    match classify_failure(text) {
        Failure::WrongPin => "wrong PIN for the security key. Check how many attempts it has \
            left with `fido2-token -I <device>` (see `fido2-token -L`) before trying again; \
            the plugin does not report the count."
            .to_string(),
        Failure::PinBlocked => "the security key has blocked PIN entry after repeated wrong \
            PINs. Unplug it, plug it back in, then try again."
            .to_string(),
        Failure::PinRequired => "the security key needs its PIN and none was given.".to_string(),
        Failure::NoDevice => "no FIDO2 security key was found (timed out waiting for a device). \
            Plug it in and retry; if several are attached, set FIDO2_TOKEN to the device path \
            shown by `fido2-token -L`."
            .to_string(),
        Failure::TouchTimeout => "timed out waiting for a touch: the key was not touched in \
            time. Try again and touch it as soon as it blinks."
            .to_string(),
        Failure::WrongKey => "the attached security key does not hold this slot's credential \
            (is it the key that was enrolled?)."
            .to_string(),
        Failure::Denied => "the security key refused the operation (operation denied); the \
            touch or PIN prompt was cancelled or not accepted."
            .to_string(),
        Failure::PluginMissing => "age-plugin-fido2-hmac is not installed or not on PATH. \
            Install v0.5.0 or later from https://github.com/olastor/age-plugin-fido2-hmac."
            .to_string(),
        Failure::PluginOld => "age-plugin-fido2-hmac is too old: TeaGarden needs v0.5.0 or \
            later (--post-quantum, -y and --algorithm)."
            .to_string(),
        Failure::UvRequired => "the security key requires user verification for every use \
            (its alwaysUv setting) and could not do it without a PIN, so it refused \
            (CTAP2_ERR_PUAT_REQUIRED). Such a key cannot unlock a touch-only slot unless it has \
            a fingerprint enrolled; enroll this key with --fido2-mode pin-up instead."
            .to_string(),
        Failure::Other => text.to_string(),
    }
}

/// Where announcements go.
pub(super) struct Announcer {
    sink: Mutex<Box<dyn Write + Send>>,
    tty: bool,
    /// The last text written did not end in a newline.
    mid_line: AtomicBool,
}

impl Announcer {
    /// The controlling terminal, or stderr when there is none.
    pub(super) fn open() -> Self {
        Self::open_path(Path::new("/dev/tty"))
    }

    /// `path` for writing, or stderr when it cannot be opened. Production uses
    /// `/dev/tty`; the path is a parameter so the fallback can be tested.
    pub(super) fn open_path(path: &Path) -> Self {
        match OpenOptions::new().write(true).open(path) {
            Ok(file) => Self {
                sink: Mutex::new(Box::new(file)),
                tty: true,
                mid_line: AtomicBool::new(false),
            },
            Err(_) => Self {
                sink: Mutex::new(Box::new(std::io::stderr())),
                tty: false,
                mid_line: AtomicBool::new(false),
            },
        }
    }

    #[cfg(test)]
    pub(super) fn from_writer(writer: Box<dyn Write + Send>) -> Self {
        Self {
            sink: Mutex::new(writer),
            tty: false,
            mid_line: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    pub(super) fn is_tty(&self) -> bool {
        self.tty
    }

    /// Best effort: a terminal that has gone away falls back to stderr, and a
    /// write failure never fails the operation.
    pub(super) fn write(&self, text: &str) {
        if !text.is_empty() {
            self.mid_line
                .store(!text.ends_with('\n'), Ordering::Relaxed);
        }
        let mut sink = lock(&self.sink);
        let wrote = sink.write_all(text.as_bytes()).and_then(|()| sink.flush());
        if wrote.is_err() && self.tty {
            let mut err = std::io::stderr();
            let _ = err.write_all(text.as_bytes());
        }
    }

    /// A whole line of our own: it starts on a fresh line even when the plugin's
    /// last message had no newline, so a banner is never glued to plugin text.
    pub(super) fn line(&self, text: &str) {
        if self.mid_line.load(Ordering::Relaxed) {
            self.write("\n");
        }
        self.write(&format!("{text}\n"));
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Default)]
struct State {
    touches: usize,
    /// A touch was announced and its outcome is not yet known.
    pending: bool,
    note: Option<String>,
}

/// Counts touches and announces them, for every message the plugin sends through
/// the age plugin protocol during one operation.
pub(super) struct TouchSession {
    announcer: Announcer,
    plan: TouchPlan,
    state: Mutex<State>,
}

impl TouchSession {
    pub(super) fn new(plan: TouchPlan, announcer: Announcer) -> Arc<Self> {
        Arc::new(Self {
            announcer,
            plan,
            state: Mutex::new(State::default()),
        })
    }

    /// Say up front what is about to be asked of the operator.
    pub(super) fn announce_plan(&self) {
        self.announcer.line(&self.plan.preamble);
    }

    /// A plugin `display_message`: touch notices become banners, anything else is
    /// shown as the plugin's own words.
    pub(super) fn on_message(&self, message: &str) {
        match classify_notice(message) {
            Some(notice) => self.notice(notice),
            None => self
                .announcer
                .line(&format!("  token: {}", message.trim_end())),
        }
    }

    fn notice(&self, notice: Notice) {
        match notice {
            Notice::SelectDevice(devices) => self.announcer.line(&select_banner(devices)),
            Notice::Touch => {
                let mut state = lock(&self.state);
                if state.pending {
                    // The plugin moved on, so the previous touch was accepted.
                    self.announcer.line(CONFIRMED);
                }
                state.touches += 1;
                state.pending = true;
                let n = state.touches;
                let purpose = self
                    .plan
                    .purposes
                    .get(n - 1)
                    .map_or("another touch", String::as_str);
                self.announcer
                    .line(&touch_banner(n, self.plan.purposes.len(), purpose));
            }
        }
    }

    /// The operation that used the touches succeeded: confirm the last one.
    pub(super) fn finish_ok(&self) {
        let mut state = lock(&self.state);
        if state.pending {
            state.pending = false;
            self.announcer.line(CONFIRMED);
        }
    }

    #[cfg(test)]
    pub(super) fn touches(&self) -> usize {
        lock(&self.state).touches
    }

    /// Remember why an operator-side step failed (e.g. no terminal for the PIN).
    pub(super) fn note(&self, note: &str) {
        lock(&self.state).note = Some(note.to_string());
    }

    pub(super) fn take_note(&self) -> Option<String> {
        lock(&self.state).note.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Write` whose contents the test can read back.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn session(plan: TouchPlan) -> (Arc<TouchSession>, Capture) {
        let capture = Capture::default();
        let session = TouchSession::new(plan, Announcer::from_writer(Box::new(capture.clone())));
        (session, capture)
    }

    // The strings below are the ones age-plugin-fido2-hmac v0.5.0 emits:
    //   pkg/plugin/identity.go  LoadSecret:  DisplayMessage("Please touch your token...")
    //   pkg/plugin/cli.go       NewCredentials: displayMessage("Please touch your token...\n")
    //   pkg/plugin/fido2_utils.go FindDevice: "Found %d devices. Please touch the one you want to use."
    // They reach TeaGarden as age plugin protocol `msg` commands (Plugin.DisplayMessage).

    #[test]
    fn display_message_maps_the_plugin_touch_notice_to_a_touch() {
        assert_eq!(
            classify_notice("Please touch your token..."),
            Some(Notice::Touch)
        );
        assert_eq!(
            classify_notice("Please touch your token...\n"),
            Some(Notice::Touch)
        );
    }

    #[test]
    fn display_message_maps_the_device_selection_notice() {
        assert_eq!(
            classify_notice("Found 2 devices. Please touch the one you want to use."),
            Some(Notice::SelectDevice(2))
        );
    }

    #[test]
    fn display_message_leaves_other_messages_alone() {
        for message in [
            "Using device path from env: /dev/hidraw3",
            "Warning: Failed to call mlock: cannot allocate memory",
            "Waiting for age-plugin-fido2-hmac...",
            "Please insert your token now...\n",
            "",
        ] {
            assert_eq!(classify_notice(message), None, "{message:?}");
        }
    }

    #[test]
    fn the_session_numbers_every_touch_and_confirms_the_previous_one() {
        let (session, out) = session(TouchPlan::enrollment(Fido2Mode::Up));
        session.on_message("Please touch your token...");
        session.on_message("Please touch your token...");
        session.finish_ok();
        assert_eq!(session.touches(), 2);
        assert_eq!(
            out.text(),
            "\
>>> Touch your security key now (touch 1 of 2: creating the credential) <<<
  ✓ key confirmed
>>> Touch your security key now (touch 2 of 2: deriving the key) <<<
  ✓ key confirmed
"
        );
    }

    #[test]
    fn a_failed_operation_does_not_confirm_its_touch() {
        let (session, out) = session(TouchPlan::unlock(Fido2Mode::Up, Some("vault")));
        session.on_message("Please touch your token...");
        assert!(!out.text().contains("confirmed"));
    }

    #[test]
    fn an_unplanned_extra_touch_is_still_announced_and_counted() {
        let (session, out) = session(TouchPlan::unlock(Fido2Mode::Up, Some("vault")));
        session.on_message("Please touch your token...");
        session.on_message("Please touch your token...");
        assert!(
            out.text()
                .contains(">>> Touch your security key now (touch 2: another touch) <<<"),
            "{}",
            out.text()
        );
    }

    #[test]
    fn a_non_touch_message_is_shown_but_not_counted() {
        let (session, out) = session(TouchPlan::unlock(Fido2Mode::Up, Some("vault")));
        session.on_message("Using device path from env: /dev/hidraw3");
        assert_eq!(session.touches(), 0);
        assert_eq!(
            out.text(),
            "  token: Using device path from env: /dev/hidraw3\n"
        );
    }

    #[test]
    fn several_keys_attached_is_announced_before_the_selection_touch() {
        let (session, out) = session(TouchPlan::unlock(Fido2Mode::Up, Some("vault")));
        session.on_message("Found 2 devices. Please touch the one you want to use.");
        let text = out.text();
        assert!(text.contains("2 security keys are attached"), "{text}");
        assert!(text.contains("FIDO2_TOKEN"), "{text}");
        assert_eq!(session.touches(), 0, "the selection touch is extra");
    }

    #[test]
    fn announcements_fall_back_to_stderr_when_the_terminal_cannot_be_opened() {
        let announcer = Announcer::open_path(Path::new("/nonexistent-dir-for-teagarden/tty"));
        assert!(!announcer.is_tty());
    }

    #[test]
    fn announcements_go_to_the_terminal_path_when_it_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tty");
        std::fs::write(&path, b"").unwrap();
        let announcer = Announcer::open_path(&path);
        assert!(announcer.is_tty());
        announcer.line(">>> hello <<<");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ">>> hello <<<\n");
    }

    #[test]
    fn failures_are_classified_from_real_plugin_text() {
        // Each string is one the plugin or age can produce:
        //  - libfido2 error names: go-libfido2 fido2.go (ErrPinInvalid, ErrPinAuthBlocked,
        //    ErrPinRequired, ErrActionTimeout, ErrNoCredentials, ErrOperationDenied)
        //  - "timed out waiting for device": fido2_utils.go FindDevice
        //  - "timeout reached before any device was touched": go-libfido2 SelectDevice
        //  - "pin required for this identity": identity.go LoadSecret
        //  - age messages: i18n/en-US/age.ftl (err-plugin-identity, err-no-matching-keys,
        //    err-missing-plugin) and our own require_plugin() text
        let cases = [
            (
                "FIDO2 unwrap failed: 'age-plugin-fido2-hmac' couldn't use an identity: pin invalid",
                Failure::WrongPin,
            ),
            ("Failed: pin invalid", Failure::WrongPin),
            (
                "'age-plugin-fido2-hmac' couldn't use an identity: pin auth blocked",
                Failure::PinBlocked,
            ),
            (
                "'age-plugin-fido2-hmac' couldn't use an identity: pin required for this identity",
                Failure::PinRequired,
            ),
            (
                "'age-plugin-fido2-hmac' couldn't use an identity: timed out waiting for device",
                Failure::NoDevice,
            ),
            ("Failed: timed out waiting for device", Failure::NoDevice),
            (
                "'age-plugin-fido2-hmac' couldn't use an identity: action timed out",
                Failure::TouchTimeout,
            ),
            (
                "Failed: timeout reached before any device was touched",
                Failure::TouchTimeout,
            ),
            ("FIDO2 unwrap failed: No matching keys found", Failure::WrongKey),
            (
                "'age-plugin-fido2-hmac' couldn't use an identity: operation denied",
                Failure::Denied,
            ),
            (
                "age-plugin-fido2-hmac not found on PATH — the FIDO2 factor needs it. Install v0.5.0 \
                 or later from https://github.com/olastor/age-plugin-fido2-hmac",
                Failure::PluginMissing,
            ),
            (
                "Could not find 'age-plugin-fido2-hmac' on the PATH.",
                Failure::PluginMissing,
            ),
            (
                "age-plugin-fido2-hmac is incompatible — TeaGarden requires v0.5.0 or later with \
                 --post-quantum, identity-to-recipient (-y), and --algorithm support",
                Failure::PluginOld,
            ),
            ("libfido2 error 99", Failure::Other),
        ];
        for (text, want) in cases {
            assert_eq!(classify_failure(text), want, "{text}");
        }
    }

    #[test]
    fn failure_descriptions_say_what_went_wrong_and_never_echo_a_pin() {
        let wrong_pin =
            describe_failure("FIDO2 unwrap failed: couldn't use an identity: pin invalid");
        assert!(wrong_pin.contains("wrong PIN"), "{wrong_pin}");
        assert!(wrong_pin.contains("fido2-token -I"), "{wrong_pin}");
        let none = describe_failure("Failed: timed out waiting for device");
        assert!(none.contains("no FIDO2 security key"), "{none}");
        assert!(none.contains("FIDO2_TOKEN"), "{none}");
        let timeout = describe_failure("couldn't use an identity: action timed out");
        assert!(
            timeout.contains("timed out waiting for a touch"),
            "{timeout}"
        );
        let missing = describe_failure("Could not find 'age-plugin-fido2-hmac' on the PATH.");
        assert!(missing.contains("not installed"), "{missing}");
        // Unknown text is passed through rather than hidden.
        assert!(describe_failure("libfido2 error 99").contains("libfido2 error 99"));
    }

    #[test]
    fn the_pin_up_enrollment_preamble_states_the_exact_sequence() {
        let plan = TouchPlan::enrollment(Fido2Mode::PinUp);
        assert_eq!(
            plan.purposes,
            ["creating the credential", "deriving the key"]
        );
        assert_eq!(
            plan.preamble,
            "\
FIDO2 enrollment, mode PIN + UP: unlocking this slot will need the key's PIN and a touch.
This enrollment asks for, in order:
  1. the key's PIN
  2. touch 1 of 2 (creating the credential)
  3. touch 2 of 2 (deriving the key)
The PIN is asked once. If the key has no PIN set, enrollment stops and the slot is not saved."
        );
    }

    #[test]
    fn the_up_enrollment_preamble_states_the_exact_sequence() {
        let plan = TouchPlan::enrollment(Fido2Mode::Up);
        assert_eq!(
            plan.purposes,
            ["creating the credential", "deriving the key"]
        );
        assert_eq!(
            plan.preamble,
            "\
FIDO2 enrollment, mode UP only: unlocking this slot will need a touch and no PIN.
This enrollment asks for, in order:
  1. the key's PIN, only if the key has one (to create the credential; unlocking never asks for it)
  2. touch 1 of 2 (creating the credential)
  3. touch 2 of 2 (deriving the key)
A key set to always verify its user (alwaysUv) also checks your fingerprint on each touch."
        );
    }

    #[test]
    fn the_unlock_notice_states_the_recorded_mode_and_its_sequence() {
        let plan = TouchPlan::unlock(Fido2Mode::PinUp, Some("fidovol"));
        assert_eq!(plan.purposes, ["unlocking the volume"]);
        assert_eq!(
            plan.preamble,
            "Unlocking 'fidovol' with FIDO2 (mode PIN + UP): enter the key's PIN, then touch the key."
        );
        assert_eq!(
            TouchPlan::unlock(Fido2Mode::Up, None).preamble,
            "Unlocking the volume with FIDO2 (mode UP only): touch the key. No PIN is asked."
        );
    }

    #[test]
    fn a_banner_is_printed_before_every_pin_entry() {
        // `Please enter you PIN:` is identity.go's stanza-unwrap prompt (the typo is
        // the plugin's); `Please enter your PIN:` is cli.go's creation-time one.
        for description in ["Please enter you PIN:", "Please enter your PIN:"] {
            assert_eq!(
                pin_prompt(description),
                ">>> Enter the PIN of your security key now <<<\n  PIN: "
            );
        }
    }

    #[test]
    fn a_key_that_demands_verification_it_cannot_do_without_a_pin_is_explained() {
        // CTAP2_ERR_PUAT_REQUIRED (0x36 = 54) is not mapped by go-libfido2
        // (fido2.go errFromCode), whose Error type prints `libfido2 error %d`.
        let text = "'age-plugin-fido2-hmac' couldn't use an identity: libfido2 error 54";
        assert_eq!(classify_failure(text), Failure::UvRequired);
        let said = describe_failure(text);
        assert!(said.contains("alwaysUv"), "{said}");
        assert!(said.contains("pin-up"), "{said}");
    }
}
