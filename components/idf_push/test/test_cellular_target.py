#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PUSH = ROOT / "components/idf_push"


def main() -> None:
    source = r'''
#include <cassert>
#include "idf_push_cellular.h"

int main() {
    IdfPushChannel channel;
    channel.enabled = true;
    channel.type = PUSH_TYPE_GOTIFY;
    channel.url = "https://Example.COM:443/base";
    IdfPushCellularTarget target;
    assert(idf_push_prepare_cellular_target(channel, target));
    assert(target.effectiveUrl == channel.url);
    assert(target.canonicalOrigin == "https://example.com");

    channel.cellularUrl = "https://Cell.Example:8443/relay";
    assert(idf_push_prepare_cellular_target(channel, target));
    assert(target.canonicalOrigin == "https://cell.example:8443");

    channel.cellularEnabled = false;
    assert(!idf_push_prepare_cellular_target(channel, target));
    assert(target.effectiveUrl.empty());
    channel.cellularEnabled = true;

    channel.cellularUrl = "http://cell.example/relay";
    assert(!idf_push_prepare_cellular_target(channel, target));
    channel.cellularUrl = "https://user@cell.example/relay";
    assert(!idf_push_prepare_cellular_target(channel, target));

    channel.cellularUrl.clear();
    channel.url.clear();
    channel.type = PUSH_TYPE_TELEGRAM;
    assert(idf_push_prepare_cellular_target(channel, target));
    assert(target.canonicalOrigin == "https://api.telegram.org");
    channel.type = PUSH_TYPE_GET;
    assert(!idf_push_prepare_cellular_target(channel, target));
}
'''
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, "esp_err.h").write_text("using esp_err_t = int;\n")
        fixture = Path(directory) / "fixture.cpp"
        binary = Path(directory) / "fixture"
        fixture.write_text(source)
        subprocess.run([
            "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
            f"-I{directory}",
            f"-I{PUSH / 'include'}", f"-I{ROOT / 'components/idf_config/include'}",
            str(PUSH / "idf_push_cellular.cpp"), str(fixture), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
