import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GObject  # noqa: E402

from netsentinel.core.audit.ledger import AuditLedger  # noqa: E402


class ConsentDialog(Adw.AlertDialog):  # type: ignore[misc]
    __gtype_name__ = "NetSentinelConsentDialog"

    def __init__(self, ledger: AuditLedger, **kwargs: object):
        super().__init__(
            title="Rules of Engagement & Legal Consent",
            body=(
                "NetSentinel is a cyber security auditing tool containing active scanning, "
                "interception (MitM), and active enumeration capabilities.\n\n"
                "By clicking 'Accept', you confirm that you own or have explicit, written "
                "authorization (Rules of Engagement) to test the target scope. "
                "All actions will be cryptographically logged for audit purposes (RE-01)."
            ),
            **kwargs,
        )
        self.ledger = ledger
        self.accepted = False

        # Add buttons
        self.add_response("decline", "Decline")
        self.add_response("accept", "Accept")

        # Style Accept button as suggested/primary
        self.set_response_appearance("accept", Adw.ResponseAppearance.SUGGESTED)
        self.set_response_appearance("decline", Adw.ResponseAppearance.DESTRUCTIVE)

        self.connect("response", self._on_response)

    def _on_response(self, _dialog: Adw.AlertDialog, response: str) -> None:
        if response == "accept":
            self.accepted = True
            # Log the consent to the audit ledger
            consent_hash = self.ledger.append(
                action="USER_LEGAL_CONSENT_ACCEPTED",
                pddl_status="VALIDATED",
                input_data="Rules of Engagement Acceptance",
            )
            # Emit a custom signal or call a callback to notify application
            self.emit("consent-resolved", True, consent_hash)
        else:
            self.accepted = False
            self.emit("consent-resolved", False, "")


# Register custom signal
GObject.signal_new(
    "consent-resolved",
    ConsentDialog,
    GObject.SignalFlags.RUN_LAST,
    GObject.TYPE_NONE,
    (GObject.TYPE_BOOLEAN, GObject.TYPE_STRING),
)
