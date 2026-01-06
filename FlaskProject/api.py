import requests
import json
from datetime import datetime, timezone

API_KEY = "37ccd71ccec744a8b1fec125dc39554c"
HEADERS = {"X-Auth-Token": API_KEY}

def get_current_matchday():
    url = "https://api.football-data.org/v4/competitions/PL"
    r = requests.get(url, headers=HEADERS, timeout=15)
    r.raise_for_status()
    data = r.json()
    return data["currentSeason"]["currentMatchday"]

def get_matches(matchday=None):
    url = "https://api.football-data.org/v4/competitions/PL/matches"
    params = {}
    if matchday is not None:
        params["matchday"] = matchday

    r = requests.get(url, headers=HEADERS, params=params, timeout=15)
    r.raise_for_status()

    data = r.json()
    matches = data.get("matches", [])
    for match in matches:
        print(json.dumps(match))
        print()

def run_for_current_week():
    md = get_current_matchday()
    print("Current matchday:", md)
    get_matches(matchday=md)

run_for_current_week()


