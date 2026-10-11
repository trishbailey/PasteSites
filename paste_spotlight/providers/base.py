"""Provider interface."""

from paste_spotlight.config import env_value
from paste_spotlight.models import Hit, ProviderResult, SearchQuery, Status


class Provider:
    id = ""
    name = ""
    summary = ""
    readiness = "ready"

    def configured(self) -> bool:
        return True

    def search(self, query: SearchQuery, client) -> ProviderResult:
        raise NotImplementedError

    def finish(self, status: Status, message: str, hits: list[Hit] | None = None) -> ProviderResult:
        return ProviderResult(
            provider_id=self.id,
            name=self.name,
            status=status,
            message=message,
            hits=hits or [],
        )


def missing_key(provider: Provider, env_name: str, how: str) -> ProviderResult | None:
    if env_value(env_name):
        return None
    return provider.finish(
        Status.NEEDS_KEY,
        f"Set {env_name}. {how}",
    )
