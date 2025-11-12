from inferas import web
from inferas import re

# demo injection
injected = web.injection.element(web.html, "<div id='injected'>yo injected</div>", where="body-end")
injected = web.injection.css(injected, "body { background: #f6f6ff }")
print("-> injected snippet exists?", "injected" in injected)

# reverse engineering

# inferas/re.py
"""
Simple local reverse-engineer helpers for legitimate debugging / analysis.
- get_pid(pid): return process metadata (uses psutil)
- get_source(pid_or_path): for a pid or executable path, return file metadata,
  sha256 and a short 'strings' extraction.

Notes:
- This runs locally and inspects only files/processes the running user can access.
- Don't use this to invade privacy, bypass auth, or break the law.
"""

from typing import Union, Dict, Any, List, Optional
import hashlib
import os
import sys
import time
import struct
import shutil

# optional dependency
try:
    import psutil
except Exception:
    psutil = None


class re:
    @staticmethod
    def _safe_psutil_proc(pid: int):
        if psutil is None:
            raise RuntimeError("psutil not installed. pip install psutil to use get_pid.")
        try:
            return psutil.Process(pid)
        except psutil.NoSuchProcess:
            return None

    @staticmethod
    def get_pid(pid: int) -> Dict[str, Any]:
        """
        Return a dictionary with metadata about the process `pid`.
        Requires psutil.
        Keys: pid, name, cmdline, exe, cwd, username, created, status, cpu_times,
              memory_info, open_files (names), connections (summary)
        """
        proc = re._safe_psutil_proc(pid)
        if proc is None:
            raise ValueError(f"No process with pid={pid}")

        out: Dict[str, Any] = {"pid": pid}
        try:
            out["name"] = proc.name()
        except Exception:
            out["name"] = None
        try:
            out["cmdline"] = proc.cmdline()
        except Exception:
            out["cmdline"] = None
        try:
            out["exe"] = proc.exe()
        except Exception:
            out["exe"] = None
        try:
            out["cwd"] = proc.cwd()
        except Exception:
            out["cwd"] = None
        try:
            out["username"] = proc.username()
        except Exception:
            out["username"] = None
        try:
            out["created"] = proc.create_time()
        except Exception:
            out["created"] = None
        try:
            out["status"] = proc.status()
        except Exception:
            out["status"] = None
        try:
            out["cpu_times"] = proc.cpu_times()._asdict()
        except Exception:
            out["cpu_times"] = None
        try:
            mem = proc.memory_info()
            # convert to readable
            out["memory_info"] = {
                "rss": getattr(mem, "rss", None),
                "vms": getattr(mem, "vms", None),
            }
        except Exception:
            out["memory_info"] = None
        try:
            out["open_files"] = [f.path for f in proc.open_files()]
        except Exception:
            out["open_files"] = None
        try:
            conns = proc.connections()
            out["connections_count"] = len(conns)
            # don't dump sockets; just a summary
        except Exception:
            out["connections_count"] = None

        return out

    @staticmethod
    def _compute_sha256(path: str, chunk_size: int = 8192) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                b = fh.read(chunk_size)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()

    @staticmethod
    def _extract_strings(path: str, min_len: int = 4, max_results: int = 200) -> List[str]:
        """
        Minimal 'strings' implementation: extract printable ASCII sequences from a binary.
        - min_len: minimum length of sequence to keep
        - max_results: limit the number of returned strings to avoid huge outputs
        """
        results: List[str] = []
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except Exception:
            return results

        printable = []
        for b in data:
            c = chr(b) if isinstance(b, int) else b  # py2/py3 safe
            if " " <= c <= "~":  # basic printable range
                printable.append(c)
            else:
                if len(printable) >= min_len:
                    s = "".join(printable)
                    results.append(s)
                    if len(results) >= max_results:
                        break
                printable = []
        # final tail
        if len(results) < max_results and len(printable) >= min_len:
            results.append("".join(printable))
        return results

    @staticmethod
    def _file_metadata(path: str) -> Dict[str, Any]:
        st = os.stat(path)
        return {
            "path": os.path.abspath(path),
            "size": st.st_size,
            "mtime": st.st_mtime,
            "ctime": st.st_ctime,
            "mode": st.st_mode,
        }

    @staticmethod
    def get_source(pid_or_path: Union[int, str], *, strings_min_len: int = 4, strings_limit: int = 200) -> Dict[str, Any]:
        """
        Given a pid (int) or an executable path (str), return metadata about the file,
        sha256, and a short printable-strings extraction.

        Returns a dict:
        {
            "source_path": str,
            "file": {metadata...},
            "sha256": str,
            "strings": [...]
        }

        Note: This reads the binary from disk. Must have filesystem permissions.
        """
        path: Optional[str] = None

        # resolve pid -> exe path
        if isinstance(pid_or_path, int):
            if psutil is None:
                raise RuntimeError("psutil not installed. pip install psutil to use pid lookup.")
            proc = re._safe_psutil_proc(pid_or_path)
            if proc is None:
                raise ValueError(f"No process with pid={pid_or_path}")
            try:
                path = proc.exe()
            except Exception:
                path = None
        else:
            path = pid_or_path

        if not path:
            raise ValueError("Could not determine executable path for the input.")

        if not os.path.exists(path):
            raise FileNotFoundError(f"Path does not exist: {path}")

        out: Dict[str, Any] = {"source_path": os.path.abspath(path)}

        try:
            out["file"] = re._file_metadata(path)
        except Exception as e:
            out["file"] = {"error": str(e)}

        try:
            out["sha256"] = re._compute_sha256(path)
        except Exception as e:
            out["sha256"] = f"error: {e}"

        # small strings extraction (be conservative)
        try:
            out["strings"] = re._extract_strings(path, min_len=strings_min_len, max_results=strings_limit)
        except Exception as e:
            out["strings"] = [f"error extracting strings: {e}"]

        # try optional extras: check if path is inside a python virtualenv or site-packages
        try:
            out["is_executable"] = os.access(path, os.X_OK)
            out["is_script_like"] = path.endswith((".py", ".pyc", ".pyo"))
            # try to guess package name for python egg/wheel paths
            out["guess_package"] = None
            lower = path.lower()
            if "site-packages" in lower or "dist-packages" in lower:
                out["guess_package"] = os.path.basename(os.path.dirname(path))
        except Exception:
            pass

        return out


# quick demo when run directly
if __name__ == "__main__":
    print("inferas.re demo")
    # check psutil availability
    if psutil is None:
        print("psutil not installed -> install with: pip install psutil")
        sys.exit(0)

    # try to inspect our own process
    mypid = os.getpid()
    print(f"inspecting pid={mypid}")
    print(re.get_pid(mypid))

    # get source (executable path for current python)
    print("getting source for current interpreter:")
    info = re.get_source(mypid, strings_limit=30)
    print("source path:", info.get("source_path"))
    print("sha256:", info.get("sha256"))
    print("first strings sample:", info.get("strings")[:5])
