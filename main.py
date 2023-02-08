import sys
import sqlite3
from sqlite3 import Error
import requests
import xml.etree.ElementTree as xml
import re
import time
from requests.auth import HTTPBasicAuth
from packaging import version
import config

cursor = None
conn = None


def main(mode, path):
    # connect to db
    conn, cursor = create_connection(r"nvd.db")
    # determine mode
    if mode == 'detectOnly':
        detectOnly(path, cursor)
    if mode == 'doAll':
        doAll(path, conn, cursor)


def detectOnly(path, cursor):
    # find dependencies
    dependencies = parse_pom(path)
    # check the db for any matches to the list of dependencies
    dbMatches = check_db(dependencies, cursor)
    # see which matches from the db match the dependencies from pom
    results = compare(dbMatches, dependencies)
    return print_output(dbMatches, results)


def doAll(path, conn, cursor):
    # delete everything from db, remake query
    # NOTE: This process takes several minutes due to the fact that multiple requests need to be made
    reloadData(conn, cursor)
    # find dependencies
    dependencies = parse_pom(path)
    # check the db for any matches to the list of dependencies
    dbMatches = check_db(dependencies, cursor)
    # see which matches from the db match the dependencies from pom
    results = compare(dbMatches, dependencies)
    return print_output(dbMatches, results)


def compare(dbMatches, dependencies):
    """ Go through each dependency and each match from the db.
        if there is a match in the uri, add it to a list (if its
        not already in the list otherwise, do nothing. return list. """
    listDep = []
    if dbMatches:
        for dependency in dependencies:
            for match in dbMatches:
                for element in match:
                    if dependency in element[1]:
                        if element[3] is None:
                            index = re.search(r":\d", element[1][7:])
                            if index is not None:
                                index = index.span()[0] + 8
                                endIndex = element[1].find('*') - 1
                                versionNum = element[1][index:endIndex]
                                """from
                                https://stackoverflow.com/questions/11887762/how-do-i-compare-version-numbers-in-python
                                """
                                if version.parse(versionNum) == version.parse(dependencies[dependency]):
                                    dep = dependency.split(":")
                                    if dep[1] not in listDep:
                                        listDep.append(dep[1])

                        else:
                            listVersions = element[3].split(',')
                            if version.parse(listVersions[0]) <= version.parse(dependencies[dependency]) <= \
                                    version.parse(listVersions[1]):
                                dep = dependency.split(":")
                                if dep[1] not in listDep:
                                    listDep.append(dep[1])

                    else:
                        break
    return listDep


def print_output(dbMatches, dependencies):
    """
    :param dbMatches: matches from the db
    :param dependencies: list of vulnerable dependencies
    :return: nothing

    open or create results.txt. If there are matches in the db, write them into file.
    Go through list of vulnerable dependencies and create lists for versions, cve, impact.
    for each match in the db, find the ones that match the current dependency.
    if there are no versions specified from the db, parse it from the uri.
    If the version is in the list of versions, don't add it again. If the CVE
    is not yet in the list of CVEs, add the new CVE and impact score.
    After going through all the dbMatches, write them to the file.

    If there are no vulnerabilities, write that in the file and close. """

    output = open('results.txt', 'w+')
    if len(dependencies) != 0:
        output.write("Known security vulnerabilities detected: \n")
        output.write('\n')
        for dependency in dependencies:
            listVersions = []
            listCVE = []
            listImpact = []
            for match in dbMatches:
                for element in match:
                    if dependency in element[1]:
                        if element[3] is None:
                            index = re.search(r"\d", element[1][7:]).span()[0] + 7
                            endIndex = element[1].find('*') - 1
                            version = element[1][index:endIndex]
                            if version in listVersions:
                                pass
                            else:
                                listVersions.append(version)
                        else:
                            listVersions = element[3].split(',')
                        if element[0] not in listCVE:
                            listCVE.append(element[0])
                            listImpact.append(element[2])
                    else:
                        break
            dependencyString = "Dependency: " + dependency
            output.write(dependencyString)
            output.write('\n')
            if len(listVersions) == 1:
                versionString = "Version(s): " + listVersions[0]
                output.write(versionString)
            else:
                versionString = "Version(s): >= " + listVersions[0] + " < " + listVersions[1]
                output.write(versionString)
            output.write('\n')
            output.write("Vulnerabilities:")
            output.write('\n')
            for i in range(len(listCVE)):
                vulnString = "-" + listCVE[i] + " Severity: " + listImpact[i]
                output.write(vulnString)
                output.write('\n')
            output.write('\n')
    else:
        output.write("No known vulnerabilities detected.")
    output.close()


def check_db(dependencies, cursor):
    """
    :param dependencies: exisitng dependencies in the pom
    :param cursor: db cursor
    :return: matches from db

    go through the dependency list and find all instances in the db where the uris are
    similar to the dependency. The dependency format is groupId:artifactid, which
    matches the format of the uri.
    """
    matches = []
    for dependency in dependencies.keys():
        input = '%' + dependency + '%'
        cursor.execute('SELECT * from cve_knowledge_base WHERE uris LIKE ?', (input,))
        matches.append(cursor.fetchall())
    return matches


def parse_pom(path):
    """
    :param path: path to pom file
    :return: dictionary of dependencies in the pom

    parse the pom file. Parse the namespace string and create a shortcut map for namespace
    (from source provided in hw details
    https://stackoverflow.com/questions/16802732/reading-maven-pom-xml-in-python/36672072#36672072)
    Find all dependencies and extract groupId, artifactId and version. Parse groupId out of
    initial format (i.e. com.groupId.code.xxx) if applicable. Combine groupId and artifactId
    to create a format similar to the uris in the db. These are the keys and the version is
    the value.
    """

    pom = xml.parse(path)
    namespace = re.match(r'\{.*\}', pom.getroot().tag).group()
    namespace = re.sub(r"[\([{})\]]", "", namespace)
    nsmap = {'m': namespace}
    dependencies = {}

    for dependency in pom.findall('./m:dependencies/m:dependency', nsmap):
        groupId = dependency.find('m:groupId', nsmap).text
        artifactId = dependency.find('m:artifactId', nsmap).text
        index = artifactId.rfind('.')
        if index != -1:
            artifactId = artifactId[index + 1:]
        version = dependency.find('m:version', nsmap).text
        first = groupId.find('.') + 1
        last = groupId[first:].find('.') + first
        if last != -1:
            groupId = groupId[first:last]
        combined = groupId + ":" + artifactId
        dependencies[combined] = version
    return dependencies


def reloadData(conn, cursor):
    cleardb(conn, cursor)
    add_to_db(conn, cursor)
    return


def cleardb(conn, cursor):
    cursor.execute('DELETE FROM cve_knowledge_base;')
    conn.commit()


def make_requests():
    """
    :return: list of cveid, uris, impact and a dictionary of versions

    NVD API only returns 2000 responses per request. There are a total of about 206,000 vulnerabilities.
    Therefore, it is necessary to make multiple requests to fill db with all the information from NVD.
    To get to 206,000, need to iterate 103 times and increase the start index by 2000 each time.
    Build URL with the appropriate start index. Call parse_json function to make the request and parse data from
    the response, updating the list of cveid, uris, impact and dict of versions each time. Return these at the end.
    """

    cveid = []
    uris = []
    impact = []
    versions = {}
    startIndex = 0
    for i in range(0, 103):
        URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=" + str(startIndex)
        cveid, uris, impact, versions = parse_json(URL, cveid, uris, impact, versions)
        startIndex += 2000
    return cveid, uris, impact, versions


def parse_json(URL, cveid, uris, impact, versions):
    """
    :param URL: URL to make request
    :param cveid: list of cveids
    :param uris: list of uris
    :param impact: list of impact/severity
    :param versions: dictionary of versions, key is uri and value is string of starting and ending version
    :return: cveid, uris, impact, versions

    Sleep for 5 seconds because the API blocks more than 50 requests in 30 seconds (when using API key). This slows
    down the speed of the program but allows for all requests to go through and not be blocked. Get json response and
    parse it to find relevant information. This is done to reduce the overall size of the db, but again does slow down
    the program.

    """
    time.sleep(5)
    auth = HTTPBasicAuth('apikey', config.API_KEY)
    response = requests.get(URL, auth=auth)
    json_response = response.json()
    tempID = ''
    tempImpact = ''
    for i in json_response['vulnerabilities']:
        tempID = i['cve']['id']
        try:
            tempImpact = i['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
        except KeyError:
            pass
        try:
            for j in i['cve']['configurations'][0]['nodes'][0]['cpeMatch']:
                cveid.append(tempID)
                impact.append(tempImpact)
                uris.append(j['criteria'])
                versions[j['criteria']] = j['versionStartIncluding'] + ", " + j['versionEndExcluding']
        except KeyError:
            pass

    return cveid, uris, impact, versions


def add_to_db(conn, cursor):
    """
    :param conn: connection to db
    :param cursor: cursor for db
    :return: None

    Get cveids, uris, impact. Add all to db. Not all CVEs give version start or end data.
    So, iterate through keys in version dict and update the rows that have this data with the version information.
    """

    cveid, uris, impact, versions = make_requests()
    for i in range(len(cveid)):
        cursor.execute('INSERT INTO cve_knowledge_base (cveid, uris, impact) VALUES(?, ?, ?)',
                       (cveid[i], uris[i], impact[i],))
    for key in versions:
        cursor.execute('UPDATE cve_knowledge_base SET versions = ? WHERE uris = ?', (versions[key], key,))

    conn.commit()


def create_connection(db_file):
    # create a database connection to a SQLite database
    global cursor, conn
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
    except Error as e:
        print(e)
    finally:
        return conn, cursor


if __name__ == "__main__":
    # ensure proper amount of arguments are passed in
    if len(sys.argv) != 3:
        print("Error: Please enter correct program arguments: mode and path to pom file.")
    mode = sys.argv[1]
    path = sys.argv[2]
    main(mode, path)
