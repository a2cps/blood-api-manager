from reactors.runtime import Reactor
import datetime
import simplejson as json
import os
import requests
import shutil
import time


def slack_notify(message, reactor):
    if reactor.settings.get('workflow', {}).get('notify', True):
        try:
            reactor.client.actors.sendMessage(
                actorId=reactor.settings.links.slackbot,
                body={
                    'message': '{0}: {1}'.format(reactor.actor_name, message)
                })
        except Exception as exc:
            reactor.logger.warn(
                'Failed to send Slack notification from {0}: {0}'.format(
                    exc, reactor.actor_name))
    else:
        reactor.logger.info(
            'Skipped sending Slack notification from {0}'.format(
                reactor.actor_name))


def main():
    r = Reactor(tapis_optional=True)
    # Generate timestamp
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    for mcc in r.settings.mccs:
        save_api(mcc, timestamp, r)


def redact_data(json_data: dict):
    """Placeholder for deny-list redaction
    """
    return json_data


def save_api(mcc: int, timestamp: str, r: object):

    timestamp_filename = os.path.join(
        os.getcwd(), '{0}-{1}-{2}.json'.format(r.settings.tapis.filename, mcc,
                                               timestamp))
    latest_filename = os.path.join(
        os.getcwd(), '{0}-{1}-{2}.json'.format(r.settings.tapis.filename, mcc,
                                              'latest'))

    files_to_upload = [timestamp_filename, latest_filename]

    try:
        r.logger.debug('Retrieving MCC {0} data from RedCAP'.format(mcc))
        tok = os.environ.get('REDCAP_TOKEN',
                             'F765A020ACF24FAA3E57566CC41DB60C')
        headers = {'Token': tok}
        data = {'op': 'blood', 'mcc': mcc}
        resp = requests.post(r.settings.redcap.custom_api,
                             headers=headers,
                             data=data)
        resp.raise_for_status()
        data = resp.json()
        r.logger.debug('RedCAP data retrieved.')
    except Exception as exc:
        slack_notify('Data retrieval from RedCAP failed: {0}'.format(exc), r)
        r.on_failure(exc)

    # Redact sensitive fields from API response
    data = redact_data(data)

    # Dump JSON data to timestamped file
    with open(timestamp_filename, 'w') as jf:
        json.dump(data, jf, separators=(',', ':'))

    # Make a copy as 'latest'
    shutil.copy2(timestamp_filename, latest_filename)

    # Upload files via Tapis files
    if r.settings.get('workflow', {}).get('upload', True):
        r.logger.debug('Uploading files... ' + str(files_to_upload))
        try:
            for fn in files_to_upload:
                r.logger.info('File {0}'.format(fn))
                r.client.files.importData(
                    systemId=r.settings.tapis.storage_system,
                    filePath=r.settings.tapis.path,
                    fileToUpload=open(fn, 'rb'))

                # Grant permission
                r.logger.info('Setting ACL')
                body = {
                    'username': r.settings.tapis.username,
                    'permission': r.settings.tapis.pem
                }
                report_path = os.path.join(r.settings.tapis.path,
                                           os.path.basename(fn))
                r.client.files.updatePermissions(
                    systemId=r.settings.tapis.storage_system,
                    filePath=report_path,
                    body=body)
        except Exception as exc:
            slack_notify('File uploads failed: {0}'.format(exc), r)
            r.on_failure(exc)
    else:
        r.logger.info('Skipping uploads')

    slack_notify(
        'Blood Draw API data for MCC {0} was processed'.format(mcc), r)


if __name__ == '__main__':
    main()
