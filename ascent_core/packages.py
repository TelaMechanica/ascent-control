"""Shared dependency/upgrade policy. No private provider implementation.

The application supplies Context from verified installation/loaded-provider state;
request bodies, UI switches and legacy edition flags are never an authority.
This module plans/refuses changes. Atomic package storage is a separate task.
"""
from dataclasses import dataclass, field
import re
from typing import Mapping

BASE = 'ascent-control'
PLUS = 'ascent-control-plus'
PLUS_PROVIDER = 'extension.ascent-control-plus'
API_VERSION = 1
_IDENTIFIER = re.compile(r'^[a-z][a-z0-9-]{0,63}$')


class PackageError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+\.\d+\.\d+', value):
        raise PackageError('VERSION_INVALID', 'A three-part numeric version is required.')
    return tuple(int(part) for part in value.split('.'))


@dataclass(frozen=True)
class Installed:
    package_id: str
    version: str
    family: str
    config_schema: int = 1


@dataclass(frozen=True)
class Context:
    app_version: str
    verified_extensions: frozenset = frozenset()
    loaded_providers: frozenset = frozenset()
    installed_widgets: Mapping[str, Installed] = field(default_factory=dict)
    loader_api: int = API_VERSION

    @property
    def product(self):
        return PLUS if PLUS in self.verified_extensions and PLUS_PROVIDER in self.loaded_providers else BASE


@dataclass(frozen=True)
class Manifest:
    package_id: str
    version: str
    kind: str
    family: str
    min_app_version: str = '0.0.0'
    requires_product: str = BASE
    config_schema: int = 1
    loader_api: int = API_VERSION

    @classmethod
    def parse(cls, value):
        fields = set(cls.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) - fields:
            raise PackageError('MANIFEST_INVALID', 'Unknown or malformed package fields.')
        try:
            result = cls(**value)
        except TypeError as exc:
            raise PackageError('MANIFEST_INVALID', 'Required package fields are missing.') from exc
        for name in (result.package_id, result.family):
            if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name):
                raise PackageError('IDENTIFIER_INVALID', 'Invalid package/family identifier.')
        version(result.version)
        version(result.min_app_version)
        if result.kind not in ('widget', 'application_extension') or result.requires_product not in (BASE, PLUS):
            raise PackageError('MANIFEST_INVALID', 'Unknown package kind or product.')
        if type(result.config_schema) is not int or result.config_schema < 1 or type(result.loader_api) is not int:
            raise PackageError('MANIFEST_INVALID', 'Invalid configuration or loader schema.')
        # Reserved identities cannot lie about ownership/dependencies/family.
        if result.package_id == PLUS and (result.kind != 'application_extension' or result.family != BASE):
            raise PackageError('RESERVED_PACKAGE_INVALID', 'Application upgrade identity cannot be a widget.')
        if result.package_id in ('mapster', 'mapster-plus') and (result.family != 'mapster' or result.kind != 'widget'):
            raise PackageError('RESERVED_PACKAGE_INVALID', 'Mapping variants share the mapping configuration family.')
        return result


@dataclass(frozen=True)
class Plan:
    action: str
    package_id: str
    previous_package: str | None
    config_namespace: str
    requires_config_migration: bool = False


def require_dependencies(package, context):
    if package.loader_api != context.loader_api:
        raise PackageError('LOADER_API_MISMATCH', 'Package loader API is incompatible.')
    if version(context.app_version) < version(package.min_app_version):
        raise PackageError('APP_UPDATE_REQUIRED', 'Update the application before this package.')
    # Policy minimum is independent of untrusted manifest declarations.
    required = PLUS if package.package_id == 'mapster-plus' else package.requires_product
    if required == PLUS and context.product != PLUS:
        raise PackageError('APPLICATION_UPGRADE_REQUIRED', 'This package requires Ascent Control+.')


def plan_install(document, context):
    package = Manifest.parse(document)
    require_dependencies(package, context)
    previous = context.installed_widgets.get(package.family) if package.kind == 'widget' else None
    if previous is None:
        return Plan('install', package.package_id, None, package.family)
    if package.config_schema != previous.config_schema:
        raise PackageError('CONFIG_MIGRATION_REQUIRED', 'A reviewed configuration migration is required.')
    if package.package_id != previous.package_id:
        if (previous.package_id, package.package_id) != ('mapster', 'mapster-plus'):
            raise PackageError('VARIANT_REPLACEMENT_BLOCKED', 'This variant replacement is not established.')
        return Plan('upgrade_variant', package.package_id, previous.package_id, package.family)
    if version(package.version) < version(previous.version):
        raise PackageError('DOWNGRADE_BLOCKED', 'Package downgrades require a separate reviewed workflow.')
    return Plan('unchanged' if package.version == previous.version else 'upgrade', package.package_id,
                previous.package_id, package.family)


def authorize_execution(document, context):
    """Call at execution, even for a previously installed package."""
    package = Manifest.parse(document)
    require_dependencies(package, context)
    return True


def require_extension_removal(package_id, context):
    if package_id == PLUS and any(p.package_id == 'mapster-plus' for p in context.installed_widgets.values()):
        raise PackageError('DEPENDENT_PACKAGES_INSTALLED', 'Remove dependent widgets before this application extension.')
    return True
