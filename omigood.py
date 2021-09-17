"""
OmiGood, an online checker for CVE-2021-38647.
"""

import logging
import os
import socket
import threading

from flask import Flask, render_template, request, jsonify
from flask_recaptcha import ReCaptcha
from flask_talisman import Talisman

from omicheck import omi_check

logging.basicConfig(level='DEBUG')
LOGGER = logging.getLogger(__name__)

app = Flask(__name__)

csp = {
    'default-src': '\'self\' \'unsafe-inline\' unpkg.com *.google.com *.gstatic.com',
    'script-src': '\'self\' \'unsafe-inline\' *.google.com *.googleapis.com *.gstatic.com'
}
Talisman(app, content_security_policy=csp) # comment this out when running in localhost for now

RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY', None)
if not RECAPTCHA_SITE_KEY:
    raise Error('RECAPTCHA_SITE_KEY not set, cannot continue.')
app.config['RECAPTCHA_SITE_KEY'] = '6LcGR3McAAAAAOO5xAiCbd352-FfolNSY-QPQ9cS'

RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY', None)
if not RECAPTCHA_SECRET_KEY:
    raise Error('RECAPTCHA_SECRET_KEY not set, cannot continue.')
app.config['RECAPTCHA_SECRET_KEY'] = '6LcGR3McAAAAACeO1zu9i31sjYGqPh3bBSh8WIuW'

recaptcha = ReCaptcha(app)

# port status
DONT_KNOW = 0
OMI_EXPOSED_BUT_NOT_VULNERABLE = 1
OMI_EXPOSED_AND_VULNERABLE = 2

# error code
CHECK_SUCCESSFUL = 0
GENERIC_ERROR = -1
FQDN_NOT_PROVIDED = -2
INVALID_FQDN = -3
CAPTCHA_ERROR = -999

def is_valid_fqdn(fqdn):
    """
    Returns True if the provided fqdn is a valid hostname or ip address,
    false otherwise.
    """
    try:
        if socket.gethostbyname(fqdn) == fqdn:
            return True # valid hostname
        if socket.gethostbyname(fqdn) != fqdn:
            return True # valid ip address
        return True
    except socket.gaierror:
        return False # not a valid hostname or ip address

@app.route('/check', methods=["POST"])
def check():
    """
    Checks if the provided fqdn is vulnerable to CVE-2021-38647.
    """
    LOGGER.debug("Validating reCAPTCHA...")

    if "g-recaptcha-response" not in request.form:
        return jsonify({
            'result':CAPTCHA_ERROR,
            'fqdn':'',
            'report':{}
        })

    if not recaptcha.verify():
        LOGGER.debug("...invalid reCAPTCHA!")
        return jsonify({
            'result':CAPTCHA_ERROR,
            'fqdn':'',
            'report':{}
        })

    LOGGER.debug("...reCAPTCHA is good!")

    LOGGER.debug("Validating fqdn...")

    if "fqdn" not in request.form:
        LOGGER.debug("...fqdn not present!")
        return jsonify({
            'result':FQDN_NOT_PROVIDED,
            'fqdn':'',
            'report':{}
        })

    fqdn = request.form['fqdn']
    if not is_valid_fqdn(fqdn):
        LOGGER.debug("...fqdn not valid! %s", fqdn)
        return jsonify({
            'result':INVALID_FQDN,
            'fqdn':'',
            'report':{}
        })

    LOGGER.debug("...valid fqdn!")

    PORTS_TO_TEST = [
        ('https', '1270'),
        ('http', '5985'),
        ('https', '5986')
    ]

    report = {}
    for PORT_TO_TEST in PORTS_TO_TEST:
        protocol = PORT_TO_TEST[0]
        port = PORT_TO_TEST[1]

        LOGGER.debug("Checking %s on %s port %s...", fqdn, protocol, port)

        url = f'{protocol}://{fqdn}:{port}'
        res = omi_check(url)

        if res == -1:
            LOGGER.debug("...%s on http port %s is not reachable.", fqdn, port)
            report[str(port)] = DONT_KNOW

        elif res == 0:
            LOGGER.debug("...%s on http port %s is reachable but not vulnerable!", fqdn, port)
            report[str(port)] = OMI_EXPOSED_BUT_NOT_VULNERABLE

        elif res == 1:
            LOGGER.debug("...%s on http port %s is vulnerable!", fqdn, port)
            report[str(port)] = OMI_EXPOSED_AND_VULNERABLE

    return jsonify({
        'result':CHECK_SUCCESSFUL,
        'fqdn':'',
        'report': report
    })

@app.route('/', methods=["GET"])
def index():
    """
    The index page.
    """
    return render_template('index.html')

threading.Thread(target=app.run, kwargs={
                 "port": 3000, "host": "0.0.0.0"}).start()
