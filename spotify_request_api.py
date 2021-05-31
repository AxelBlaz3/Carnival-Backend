import asyncio
from datetime import time
from os import access
from aiohttp.helpers import BasicAuth
import flask.globals
from flask import session
from flask import current_app
import traceback
import time

SPOTIFY_WEB_API_BASE_URL = 'https://api.spotify.com/v1'
SPOTIFY_SHOWS_END_POINT = '/shows'
SPOTIFY_SHOW_EPISODES_ENDPOINT = '/{}/episodes'
SPOTIFY_WEB_API_GET_TOKEN_URL = 'https://accounts.spotify.com/api/token'
SPOTIFY_EPISODE_LIMIT = 20


async def fetch_shows(podcast_ids, region, client_session):
    try:
        if 'SPOTIFY_ACCESS_TOKEN' not in session or 'created_at' not in session or 'SPOTIFY_ACCESS_TOKEN_EXPIRES_IN' not in session:
            access_token = await get_spotify_access_token(client_session=client_session)
            if access_token is None:
                raise Exception('Could not get spotify access token.')
        elif time.time() - session['created_at'] > session['SPOTIFY_ACCESS_TOKEN_EXPIRES_IN'] - 60:
            access_token = await get_spotify_access_token(client_session=client_session)
            if access_token is None:
                raise Exception('Could not get spotify access token.')

        url = SPOTIFY_WEB_API_BASE_URL + SPOTIFY_SHOWS_END_POINT
        return await get_final_podcasts_response(url=url, region=region, podcast_ids=podcast_ids, client_session=client_session)
    except:
        print('Here I am')
        traceback.print_exc()
        pass
    return []


async def get_spotify_access_token(client_session):
    try:
        response = await client_session.post(SPOTIFY_WEB_API_GET_TOKEN_URL,
                                             data={
                                                 'grant_type': 'client_credentials'},
                                             auth=BasicAuth(current_app.config['SPOTIFY_CLIENT_ID'], current_app.config['SPOTIFY_CLIENT_SECRET']))
        response.raise_for_status()
        if response.status == 200:
            token_json = await response.json()
            session['SPOTIFY_ACCESS_TOKEN'] = token_json['access_token']
            session['created_at'] = time.time()
            session['SPOTIFY_ACCESS_TOKEN_EXPIRES_IN'] = token_json['expires_in']
            return token_json['access_token']
    except:
        traceback.print_exc()
        pass
    return None


async def get_final_podcasts_response(url, region, podcast_ids, client_session):
    headers = {"Authorization": f"Bearer {session['SPOTIFY_ACCESS_TOKEN']}"}
    response = await client_session.get(url=url,
                                        params={'market': region,
                                                'ids': ','.join(podcast_ids)},
                                        headers=headers)
    response.raise_for_status()
    if response.status == 200:
        podcasts = await response.json()
        flask.globals.g.overall_run_time = 0
        flask.globals.g.avg_runtime = 0
        podcasts = await asyncio.gather(*[get_episode_avg_runtime(client_session=client_session, region=region, podcast=podcast, headers=headers) for podcast in podcasts['shows']])
        podcast_response = {}
        podcast_response['podcasts'] = podcasts
        podcast_response['total_runtime'] = flask.globals.g.overall_run_time
        podcast_response['avg_runtime'] = flask.globals.g.avg_runtime // len(podcasts)
        return podcast_response
    if response.status == 404:
        return []


async def get_episode_avg_runtime(client_session, region, podcast, headers):
    response = await client_session.get(url=SPOTIFY_WEB_API_BASE_URL + SPOTIFY_SHOWS_END_POINT + f'{SPOTIFY_SHOW_EPISODES_ENDPOINT}'.format(podcast['id']),
                                  params={'market': region},
                                  headers=headers)
    response.raise_for_status()
    if response.status == 200:
        avg_runtime = 0
        total_runtime = 0
        response_json = await response.json()
        episodes = response_json['items']
        for episode in episodes:
            episode_duration_in_min = episode['duration_ms'] // 6000
            avg_runtime = avg_runtime + episode_duration_in_min
            total_runtime = total_runtime + episode_duration_in_min
        podcast['avg_runtime'] = avg_runtime // SPOTIFY_EPISODE_LIMIT
        podcast['total_runtime'] = total_runtime
        flask.globals.g.avg_runtime = flask.globals.g.avg_runtime + podcast['avg_runtime']
        flask.globals.g.overall_run_time = flask.globals.g.overall_run_time + total_runtime
        return podcast
    elif response.status == 404:
        podcast['avg_runtime'] = 0
        podcast['total_runtime'] = 0
        return podcast