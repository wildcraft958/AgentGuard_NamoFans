"""
AgentGuard – Blocklist Manager module.

Manages Azure Content Safety custom blocklists. Syncs blocklist definitions
from agentguard.yaml to Azure on initialization, then provides blocklist
names for use with ContentFilters.analyze_text().

Uses the same CONTENT_SAFETY_ENDPOINT / CONTENT_SAFETY_KEY as ContentFilters.
"""

import logging
import os

from dotenv import load_dotenv

from azure.ai.contentsafety import BlocklistClient
from azure.ai.contentsafety.models import (
    TextBlocklist,
    TextBlocklistItem,
    AddOrUpdateTextBlocklistItemsOptions,
)
from azure.core.credentials import AzureKeyCredential
from azure.core.exceptions import HttpResponseError

load_dotenv()

logger = logging.getLogger("agentguard.blocklist_manager")


class BlocklistManager:
    """Manages Azure Content Safety custom blocklists.

    Reads blocklist definitions from YAML config and syncs them to Azure.
    Returns the list of active blocklist names for use in analyze_text().
    """

    def __init__(self, endpoint: str = None, key: str = None):
        self.endpoint = endpoint or os.environ.get("CONTENT_SAFETY_ENDPOINT", "")
        self.key = key or os.environ.get("CONTENT_SAFETY_KEY", "")

        if not self.endpoint or not self.key:
            raise ValueError(
                "CONTENT_SAFETY_ENDPOINT and CONTENT_SAFETY_KEY must be set "
                "either as arguments or environment variables."
            )

        self.client = BlocklistClient(
            self.endpoint, AzureKeyCredential(self.key)
        )
        self._synced_names: list[str] = []

    def sync_blocklists(self, blocklists_config: list) -> list[str]:
        """Sync blocklist definitions from YAML config to Azure.

        Creates blocklists and adds terms. Idempotent — safe to call repeatedly.

        Args:
            blocklists_config: List of blocklist dicts from YAML, each with
                               'name', 'description', and 'terms' keys.

        Returns:
            List of blocklist names that were successfully synced.
        """
        synced = []

        for bl_cfg in blocklists_config:
            name = bl_cfg.get("name", "")
            description = bl_cfg.get("description", "")
            terms = bl_cfg.get("terms", [])

            if not name:
                logger.warning("Skipping blocklist with no name")
                continue

            try:
                self._create_blocklist(name, description)
                if terms:
                    self._add_terms(name, terms)
                synced.append(name)
                logger.info(
                    "Blocklist '%s' synced (%d terms)", name, len(terms)
                )
            except HttpResponseError as e:
                logger.error(
                    "Failed to sync blocklist '%s': %s", name, e.message
                )

        self._synced_names = synced
        return synced

    @property
    def blocklist_names(self) -> list[str]:
        """Return the list of synced blocklist names."""
        return list(self._synced_names)

    def _create_blocklist(self, name: str, description: str):
        """Create or update a blocklist."""
        self.client.create_or_update_text_blocklist(
            blocklist_name=name,
            options=TextBlocklist(blocklist_name=name, description=description),
        )

    def _add_terms(self, name: str, terms: list[str]):
        """Add terms to a blocklist."""
        items = [TextBlocklistItem(text=term) for term in terms]
        self.client.add_or_update_blocklist_items(
            blocklist_name=name,
            options=AddOrUpdateTextBlocklistItemsOptions(blocklist_items=items),
        )
