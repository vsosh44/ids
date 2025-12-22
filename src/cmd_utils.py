from subprocess import Popen, PIPE

def run_cmd(cmd: str) -> tuple[int, str, str]:
    list_cmd = cmd.split()
    p = Popen(list_cmd, stdout=PIPE, stderr=PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err
