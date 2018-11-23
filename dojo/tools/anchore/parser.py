import re
import json

from dojo.models import Finding


class AnchoreJSONParser(object):
    def __init__(self, filename, test):
        dupes = dict()
        report = json.loads(filename.read())
        findings = report.get('data')
        for finding in findings:
            image_tag, cve, severity, vuln_package, fix, url = finding

            url = re.findall(r'<.*>(.*?)<.*>', url)[0]
            # Normalization of severities
            if severity == "Negligible" or severity == "Unknown":
                severity = "Info"

            description = '{severity} vulnerability found in {package}. `Image: {image}` More details: [{cve}]({url})'.format(
                severity=severity,
                package=vuln_package,
                image=image_tag,
                cve=cve,
                url=url
                )
            if fix == 'None':
                mitigation = description
            else:
                mitigation = 'Please upgrade {package} to {fix}. More details: [{cve}]({url})'.format(
                package=vuln_package,
                fix=fix,
                cve=cve,
                url=url
                )
            title = 'Component {package} is vulnerable to {cve}'.format(
                package=vuln_package,
                cve=cve
            )
            impact = "N/A"
            references = "N/A"

            dupe_key = '{tag}{cve}{package}'.format(
                tag=image_tag,
                cve=cve,
                package=vuln_package
            )

            if dupe_key in dupes:
                finding = dupes[dupe_key]
            else:
                finding = Finding(
                    title=title,
                    cwe=0,
                    severity=severity,
                    description=description,
                    mitigation=mitigation,
                    impact=impact,
                    references=references,
                    test=test,
                    active=False,
                    verified=False,
                    numerical_severity=Finding.get_numerical_severity(severity),
                    static_finding=True,
                    url='N/A',
                    endpoints='N/A'
                )
                dupes[dupe_key] = finding

        self.items = dupes.values()

