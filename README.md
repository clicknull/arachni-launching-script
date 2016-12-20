## What is it?

This is a script intended to make launching of Arachni scanner a little bit easier, by offering some intuitive switches/options that will be translated into Arachni's own launch parameters (which are bit unintuitive in my humble opinion, hard to rembember at least). Also, the script itself manages of reports stored at project's location. 

Besides it handles raport generation into form of HTML, and autologin scripts creation in forms of: js, browser and script. 

## Example usage:

Example usages on **bWAPP** web application:

```
./arachni.py --login script --login-url /login.php --login-params "login=bee&password=bug&security_level=0&form=submit" http://192.168.56.102/bWAPP
```


With log in facility:

```
        $ arachni.py --login script --login-url /login.php --login-params "login=bee&password=bug&security_level=0&form=submit" \
            --proxy localhost:8888 http://192.168.56.102/bWAPP
```

Which produces:

```
        $ /usr/bin/arachni --plugin=login_script:script="/tmp/tmpH8Ifkm" --http-proxy localhost:8888 --output-only-positives \
                --scope-exclude-file-extensions js,jpg,jpeg,png,gif,bmp,woff,tiff,css,less --scope-exclude-binaries --scope-auto-redundant=3 --audit-links --audit-forms \
                --audit-cookies --audit-headers --audit-with-extra-parameter --http-user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0" \
                --browser-cluster-ignore-images --timeout 0:30:0 --timeout-suspend --plugin=metrics --plugin=waf_detector --plugin=autothrottle --plugin=discovery \
                --plugin=uncommon_headers --scope-include-pattern="/bWAPP" --report-save-path="/root/work/192.168.56.102/bWAPP/" --snapshot-save-path="/root/work/192.168.56.102/bWAPP/" \
                --plugin=exec:during="nikto -host __URL_HOST__ -port __URL_PORT__ -output '/root/work/192.168.56.102/bWAPP/nikto.log'" http://192.168.56.102/bWAPP 
```

TODO:
- handle some minor issues
