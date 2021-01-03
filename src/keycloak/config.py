# -*- coding: utf-8 -*-
import json
import os
import logging
from typing import Dict
from dataclasses import dataclass, fields
from functools import lru_cache

import requests
from cached_property import cached_property

from django.conf import settings

from .constants import EnvVar, Defaults, FileMode, Logger
from .utils import Singleton


log = logging.getLogger(Logger.name)


class DataClassMixin:
    def __init__(self, **kwargs: Dict):
        attrs = [x.name for x in fields(self)]
        for key, val in kwargs.items():
            key = key.replace("-", "_")
            if key in attrs:
                setattr(self, key, val)


@dataclass(init=False)
class Client(DataClassMixin):
    @property
    def realm(self) -> str:
        return settings.KEYCLOAK_REALM

    @property
    def auth_server_url(self) -> str:
        return settings.KEYCLOAK_AUTH_SERVER_URL

    @property
    def ssl_required(self) -> str:
        return settings.KEYCLOAK_SSL_REQUIRED

    @property
    def resource(self) -> str:
        return settings.KEYCLOAK_RESOURCE

    @property
    def verify_token_audience(self) -> bool:
        return settings.KEYCLOAK_VERIFY_TOKEN_AUDIENCE

    @property
    def credentials(self) -> Dict:
        return settings.KEYCLOAK_CREDENTIALS

    @property
    def confidential_port(self) -> int:
        return settings.KEYCLOAK_CONFIDENTIAL_PORT

    @property
    def policy_enforcer(self) -> Dict:
        return settings.KEYCLOAK_POLICY_ENFORCER

    @property
    def client_id(self) -> str:
        return self.resource

    @property
    def client_secret(self) -> str:
        return self.credentials["secret"]


@dataclass(init=False)
class OpenId(DataClassMixin):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    end_session_endpoint: str
    jwks_uri: str
    introspection_endpoint: str


@dataclass(init=False)
class Uma2(DataClassMixin):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    end_session_endpoint: str
    jwks_uri: str
    resource_registration_endpoint: str
    permission_endpoint: str
    policy_endpoint: str
    introspection_endpoint: str

    @property
    def resource_endpoint(self) -> str:
        return self.resource_registration_endpoint


class Config(metaclass=Singleton):
    @property
    def settings_file(self) -> str:
        log.debug("Lookup settings file in the env vars")
        return os.getenv(EnvVar.keycloak_settings, Defaults.keycloak_settings)

    @cached_property
    def client(self) -> Client:
        log.debug("Loading client config from the settings file")
        with open(self.settings_file, FileMode.read_only) as stream:
            data = json.loads(stream.read())
            return Client(**data)

    @property
    def openid_endpoint(self) -> str:
        auth_server_url = self.client.auth_server_url.rstrip("/")
        return (
            auth_server_url
            + "/realms/"
            + self.client.realm
            + "/.well-known/openid-configuration"
        )

    @cached_property
    def openid(self) -> OpenId:
        log.debug("Loading openid config using well-known endpoint")
        response = requests.get(self.openid_endpoint)
        response.raise_for_status()
        data = response.json()
        return OpenId(**data)

    @property
    def uma_endpoint(self) -> str:
        auth_server_url = self.client.auth_server_url.rstrip("/")
        return (
            auth_server_url
            + "/realms/"
            + self.client.realm
            + "/.well-known/uma2-configuration"
        )

    @cached_property
    def uma2(self) -> Uma2:
        log.debug("Loading uma2 config using well-known endpoint")
        response = requests.get(self.uma_endpoint)
        response.raise_for_status()
        data = response.json()
        return Uma2(**data)


config: Config = Config()
