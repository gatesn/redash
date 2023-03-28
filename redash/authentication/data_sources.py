import logging

import requests
from flask import abort, redirect, url_for, Blueprint, request, session
from psycopg2 import IntegrityError

from redash import models
from redash.authentication.org_resolving import current_org
from redash.utils.configuration import ValidationError
from authlib.integrations.requests_client import OAuth2Session

from redash.query_runner import query_runners, get_configuration_schema_for_query_runner_type
from redash.utils import generate_token


def create_data_sources_oauth_blueprint():
    logger = logging.getLogger("data_sources_oauth")
    blueprint = Blueprint("data_sources_oauth", __name__)

    def get_oauth_config(data_source_type):
        query_runner_cls = query_runners.get(data_source_type)
        if not query_runner_cls:
            abort(400)

        oauth_config = query_runner_cls.oauth_configuration()
        if not oauth_config:
            abort(400)

        return oauth_config

    @blueprint.route("/oauth/data_sources/<data_source_id>/authorize", endpoint="authorize")
    def authorize(data_source_id):
        data_source = models.DataSource.get_by_id_and_org(
            int(data_source_id), current_org._get_current_object()
        )

        oauth_config = get_oauth_config(data_source.type)
        oauth = OAuth2Session(
            client_id=oauth_config['client_id'],
            client_secret=oauth_config['client_secret'],
            redirect_uri=url_for(".callback", data_source_type=data_source.type, _external=True),
            scope=oauth_config['scopes'],
        )

        # Check if we're using Pushed Authorization Requests
        if oauth_config['par_uri']:
            state = generate_token(32)

            par_resp = requests.post(
                oauth_config['par_uri'],
                data={
                    'client_id': oauth_config['client_id'],
                    'redirect_uri': oauth.redirect_uri,
                    'scope': oauth.scope,
                    'response_type': 'code',
                    'state': state,
                    **oauth_config['extra_params']
                },
                auth=(oauth_config['client_id'], oauth_config['client_secret'])
            )
            if not par_resp.ok:
                raise Exception(par_resp.text)
            request_uri = par_resp.json()['request_uri']

            authorization_url = oauth_config['auth_uri'] + f"?client_id={oauth_config['client_id']}&request_uri={request_uri}"
        else:
            authorization_url, state = oauth.create_authorization_url(
                oauth_config['auth_uri'],
                access_type='offline',
                **oauth_config['extra_params'],
            )

        logger.debug("Authorizing user for data source %s", data_source)

        session['oauth_state'] = state
        session['data_source_id'] = data_source_id

        return redirect(authorization_url)

    @blueprint.route("/oauth/data_sources/<data_source_type>/callback", endpoint="callback")
    def callback(data_source_type):
        oauth_config = get_oauth_config(data_source_type)
        oauth = OAuth2Session(
            client_id=oauth_config['client_id'],
            client_secret=oauth_config['client_secret'],
            redirect_uri=url_for(".callback", data_source_type=data_source_type, _external=True),
            token_endpoint=oauth_config['token_uri'],
            scope=''.join(oauth_config.get('scopes') or [])
        )

        print("SESSION", session)

        state = session.pop('oauth_state')
        token = oauth.fetch_access_token(
            authorization_response=request.url,
            grant_type='authorization_code',
            state=state,
        )
        print("TOKEN", token)

        data_source_id = session.pop('data_source_id')
        if not data_source_id:
            abort(400)

        data_source = models.DataSource.get_by_id_and_org(
            data_source_id, current_org._get_current_object()
        )

        schema = get_configuration_schema_for_query_runner_type(data_source.type)
        if schema is None:
            abort(400)
        try:
            data_source.options.set_schema(schema)
            data_source.options.update(token)
        except ValidationError:
            abort(400)

        models.db.session.add(data_source)

        try:
            models.db.session.commit()
        except IntegrityError as e:
            abort(400)

        return redirect(f'/data_sources/{data_source.id}')

    return blueprint
