//! What a FIDO2 slot makes the security key check each time it unlocks.
//!
//! The operator chooses one of five modes at enrollment. Two can be enforced with
//! `age-plugin-fido2-hmac` v0.5.0; three cannot, and are refused with the reason
//! instead of being recorded under a name they would not live up to.

/// The verification a FIDO2 slot demands at unlock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Fido2Mode {
    /// The key's PIN, without a touch.
    Pin,
    /// The key's PIN and a touch.
    PinUp,
    /// The key's PIN and built-in user verification (a fingerprint).
    PinUv,
    /// A touch.
    Up,
    /// Built-in user verification (a fingerprint), without a PIN.
    Uv,
}

/// Why `pin` cannot be enforced. Sources: `getHmacSecret` in the plugin's
/// pkg/plugin/fido2_utils.go leaves `AssertionOpts.UP` at its default, which
/// go-libfido2 maps to `FIDO_OPT_OMIT`; CTAP 2.1 section 6.2.2 step 4.5 treats an
/// absent "up" as true; section 12.5 (hmac-secret) says a key returns
/// CTAP2_ERR_UNSUPPORTED_OPTION when "up" is false.
const PIN_ONLY_REASON: &str = "a PIN without a touch needs the key to answer with \"up\"=false. \
     age-plugin-fido2-hmac v0.5.0 never sets that option, so the key treats it as true and \
     waits for a touch; and CTAP 2.1 (section 12.5, hmac-secret) has the key refuse \"up\"=false \
     with CTAP2_ERR_UNSUPPORTED_OPTION. Every FIDO2 unlock needs a touch. Choose pin-up instead.";

/// Why `pin-uv` cannot be enforced. Sources: CTAP 2.1 section 6.2.2 step 4.2 (with
/// a pinUvAuthParam the "uv" option is treated as false; platforms MUST NOT send
/// both) and section 12.5 (the hmac-secret output depends only on the uv bit).
const PIN_UV_REASON: &str = "CTAP2 cannot require both. A PIN and a fingerprint are two ways \
     of doing the same user verification: when a PIN is given the key ignores the \"uv\" option \
     (CTAP 2.1 section 6.2.2), and hmac-secret returns the same secret whichever was used (it \
     only sees that verification happened, section 12.5). A slot cannot tell a PIN from a \
     fingerprint. Choose pin-up instead.";

/// Why `uv` cannot be enforced. Sources: the plugin passes no PIN (go-libfido2
/// turns "" into NULL) and omits "uv" for a credential that does not require a PIN,
/// so libfido2 (src/assert.c, `fido_dev_get_assert_tx`) requests no user
/// verification; whether the key verifies anyway is its alwaysUv setting (CTAP 2.1
/// section 6.2.2 step 5.4).
const UV_ONLY_REASON: &str = "age-plugin-fido2-hmac v0.5.0 never asks the key for built-in user \
     verification: without a PIN it sends no \"uv\" option. Whether the key reads a fingerprint \
     is then decided by the key's own alwaysUv setting, which TeaGarden can neither request nor \
     check through the plugin, so a slot recorded as UV could be enforcing only a touch. Choose \
     pin-up, or up (a key with alwaysUv set will still check your fingerprint on each touch, but \
     TeaGarden does not claim it).";

impl Fido2Mode {
    /// Every mode, in the order the operator is offered them.
    pub const ALL: [Self; 5] = [Self::Pin, Self::PinUp, Self::PinUv, Self::Up, Self::Uv];

    /// The name used by `--fido2-mode` and recorded in the slot.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pin => "pin",
            Self::PinUp => "pin-up",
            Self::PinUv => "pin-uv",
            Self::Up => "up",
            Self::Uv => "uv",
        }
    }

    /// The mode with this exact name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == name)
    }

    /// The short title the operator chooses by.
    pub fn title(self) -> &'static str {
        match self {
            Self::Pin => "PIN only",
            Self::PinUp => "PIN + UP",
            Self::PinUv => "PIN + UV",
            Self::Up => "UP only",
            Self::Uv => "UV only",
        }
    }

    /// What the key checks, in plain words.
    pub fn description(self) -> &'static str {
        match self {
            Self::Pin => "the key's PIN, without a touch",
            Self::PinUp => "the key's PIN and a touch",
            Self::PinUv => "the key's PIN and a fingerprint (built-in user verification)",
            Self::Up => "a touch",
            Self::Uv => "a fingerprint (built-in user verification), without a PIN",
        }
    }

    /// Why this mode cannot be enforced, or `None` when it can.
    pub fn unavailable_reason(self) -> Option<&'static str> {
        match self {
            Self::PinUp | Self::Up => None,
            Self::Pin => Some(PIN_ONLY_REASON),
            Self::PinUv => Some(PIN_UV_REASON),
            Self::Uv => Some(UV_ONLY_REASON),
        }
    }

    /// Refuse a mode that cannot be enforced, saying why.
    pub fn ensure_available(self) -> crate::error::Result<()> {
        match self.unavailable_reason() {
            None => Ok(()),
            Some(reason) => Err(crate::error::MfaError::Factor(format!(
                "FIDO2 mode {} ({}) is not available: {reason}",
                self.as_str(),
                self.title()
            ))),
        }
    }

    /// Whether the credential is created with the plugin's "require a PIN for
    /// decryption" answer set to yes. Only meaningful for an available mode.
    pub fn requires_pin(self) -> bool {
        matches!(self, Self::Pin | Self::PinUp | Self::PinUv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mode_has_a_stable_name_that_parses_back() {
        let names: Vec<&str> = Fido2Mode::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(names, ["pin", "pin-up", "pin-uv", "up", "uv"]);
        for mode in Fido2Mode::ALL {
            assert_eq!(Fido2Mode::from_name(mode.as_str()), Some(mode));
        }
        assert_eq!(Fido2Mode::from_name("PIN-UP"), None, "names are exact");
        assert_eq!(Fido2Mode::from_name("touch"), None);
    }

    #[test]
    fn every_mode_has_the_title_the_operator_chose_by() {
        let titles: Vec<&str> = Fido2Mode::ALL.iter().map(|m| m.title()).collect();
        assert_eq!(
            titles,
            ["PIN only", "PIN + UP", "PIN + UV", "UP only", "UV only"]
        );
        assert_eq!(Fido2Mode::PinUp.description(), "the key's PIN and a touch");
        assert_eq!(Fido2Mode::Up.description(), "a touch");
        assert_eq!(
            Fido2Mode::Pin.description(),
            "the key's PIN, without a touch"
        );
        assert_eq!(
            Fido2Mode::PinUv.description(),
            "the key's PIN and a fingerprint (built-in user verification)"
        );
        assert_eq!(
            Fido2Mode::Uv.description(),
            "a fingerprint (built-in user verification), without a PIN"
        );
    }

    #[test]
    fn only_pin_up_and_up_are_available() {
        let available: Vec<Fido2Mode> = Fido2Mode::ALL
            .into_iter()
            .filter(|m| m.unavailable_reason().is_none())
            .collect();
        assert_eq!(available, [Fido2Mode::PinUp, Fido2Mode::Up]);
        assert!(Fido2Mode::PinUp.ensure_available().is_ok());
        assert!(Fido2Mode::Up.ensure_available().is_ok());
    }

    #[test]
    fn pin_only_is_refused_because_every_hmac_secret_assertion_needs_a_touch() {
        let reason = Fido2Mode::Pin.unavailable_reason().unwrap();
        assert!(reason.contains("\"up\"=false"), "{reason}");
        assert!(reason.contains("never sets"), "{reason}");
        assert!(reason.contains("CTAP2_ERR_UNSUPPORTED_OPTION"), "{reason}");
        assert!(reason.contains("pin-up"), "{reason}");
    }

    #[test]
    fn pin_plus_uv_is_refused_because_ctap2_cannot_tell_a_pin_from_a_fingerprint() {
        let reason = Fido2Mode::PinUv.unavailable_reason().unwrap();
        assert!(reason.contains("cannot require both"), "{reason}");
        assert!(reason.contains("same secret"), "{reason}");
        assert!(reason.contains("pin-up"), "{reason}");
    }

    #[test]
    fn uv_only_is_refused_because_the_plugin_never_requests_user_verification() {
        let reason = Fido2Mode::Uv.unavailable_reason().unwrap();
        assert!(reason.contains("never asks the key for built-in user verification"));
        assert!(reason.contains("alwaysUv"), "{reason}");
        assert!(reason.contains("only a touch"), "{reason}");
    }

    #[test]
    fn the_refusal_names_the_mode_and_gives_the_reason() {
        for mode in [Fido2Mode::Pin, Fido2Mode::PinUv, Fido2Mode::Uv] {
            let err = format!("{}", mode.ensure_available().unwrap_err());
            assert!(err.contains(mode.as_str()), "{err}");
            assert!(err.contains(mode.title()), "{err}");
            assert!(err.contains("is not available"), "{err}");
            assert!(err.contains(mode.unavailable_reason().unwrap()), "{err}");
        }
    }

    #[test]
    fn only_pin_up_requires_the_pin_at_unlock() {
        assert!(Fido2Mode::PinUp.requires_pin());
        assert!(!Fido2Mode::Up.requires_pin());
    }
}
