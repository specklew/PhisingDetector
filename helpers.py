import datetime
import io
from contextlib import redirect_stdout

import whois

epochTime = datetime.datetime(1970, 1, 1)


def get_whois_data(domain):
    try:
        trap = io.StringIO()
        #with redirect_stdout(trap):
            # Look up the whois information
        result = whois.whois(domain)

        return result
    except:
        # Return null if the domain is not registered
        return None


def get_creation_time(domain):
    try:
        result = (domain.creation_date[0] - epochTime).total_seconds()
        return result
    except:
        return 0.0


def get_expiration_date(domain):
    try:
        result = (domain.expiration_date[0] - epochTime).total_seconds()
        return result
    except:
        return 0.0


def get_country(domain):
    try:
        result = domain.country
        return result
    except:
        return "None"


def get_registrar(domain):
    try:
        result = len(domain.registrar)
        return result
    except:
        return 0.0


def time_convert(sec):
    mins = sec // 60
    sec = sec % 60
    hours = mins // 60
    mins = mins % 60
    return "{0}:{1}:{2}".format(int(hours), int(mins), int(sec))
