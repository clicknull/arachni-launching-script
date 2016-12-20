#!/usr/bin/python

#
# Simple script that is a wrapper for the nice Arachni Web Application Scanner.
#
# The motivation behind this script is to ease setup of the arachni by passing only
# parameters that are crucial like URL, login parameters. This let's the user skip the 
# boring task of digging through tool's help/documentation and focus on actual tool launch.
# Also, the script right after arachni finishes it's job is able to launch arachni_reporter,
# process generated report file, unpack them and suggest command to view obtained index.html 
# with report in firefox browser.
#

#
# Coded by Mariusz B., mgeeky, 15-16
#

from optparse import OptionParser, OptionGroup
from os.path import expanduser, join
import sys, os, commands, re, glob, random
import tempfile, zipfile, textwrap


SCRIPT_VERSION                  = "0.5"

DEFAULT_WORK_PATH               = expanduser('~') + '/work/'

PROXY_REGEX                     = r'(?:http://|https://)?(.+):(\d+)'
DEFAULT_USER_AGENT              = "Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0"
DEFAULT_LOGOUT_PATTERN          = 'logout|logoff|signoff|signout|exit|quit|wylog'
DEFAULT_LOGIN_CHECK_PATTERN     = 'logout|logoff|lylog|witaj|welcome|hello'
EXCLUDED_COMMON_EXTENSIONS      = 'js,jpg,jpeg,png,gif,bmp,woff,woff2,tiff,css,less,pdf,doc,docx,xls,xlsx,rtf,swf'
HOST_TO_DIR_REGEX               = "^(?:([^\:]*)\:\/\/)?(?:(?:[^\:\@]*)(?:\:(?:[^\@]*))?\@)?((?:(?:[^\/\:]*)\.(?:"\
                                "[^\.\/\:]*\.[^\.\/\:]*))?(?:[^\.\/\:]*)(?:\.(?:[^\/\.\:]*))?(?:\:(?:[0-9]*))?"\
                                ")((\/[^\?#]*(?=.*?\/)\/)?(?:[^\?#]*)?)(?:\?(?:[^#]*))?(?:#(?:.*))?$"

'''
Example usage:

        ./arachni.py --login script --login-url /login.php --login-params "login=bee&password=bug&security_level=0&form=submit" http://192.168.56.102/bWAPP


With log in facility:

        $ arachni.py --login script --login-url /login.php --login-params "login=bee&password=bug&security_level=0&form=submit" \
            --proxy localhost:8888 http://192.168.56.102/bWAPP

Produces:
        $ /root/tools/arachni-build-dir/arachni/bin/arachni --plugin=login_script:script="/tmp/tmpH8Ifkm" --http-proxy localhost:8888 --output-only-positives \
                --scope-exclude-file-extensions js,jpg,jpeg,png,gif,bmp,woff,tiff,css,less --scope-exclude-binaries --scope-auto-redundant=3 --audit-links --audit-forms \
                --audit-cookies --audit-headers --audit-with-extra-parameter --http-user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0" \
                --browser-cluster-ignore-images --timeout 0:30:0 --timeout-suspend --plugin=metrics --plugin=waf_detector --plugin=autothrottle --plugin=discovery \
                --plugin=uncommon_headers --scope-include-pattern="/bWAPP" --report-save-path="/root/work/192.168.56.102/bWAPP/" --snapshot-save-path="/root/work/192.168.56.102/bWAPP/" \
                --plugin=exec:during="nikto -host __URL_HOST__ -port __URL_PORT__ -output '/root/work/192.168.56.102/bWAPP/nikto.log'" http://192.168.56.102/bWAPP 
'''

def parse_options():

        usage = "Usage: %prog [options] url"
        parser = OptionParser(usage=usage, version="%prog " + SCRIPT_VERSION)

        parser.add_option(      "-v", "--verbose", help="Displays verbose output", action="store_true")
        parser.add_option(      "-P", "--arachni", metavar="PATH", dest="arachnipath", help="Specify alternative path of the Arachni scanner binary. By default result of 'which arachni' will be used.")
        parser.add_option(      "-s", "--scanning", default="active", metavar="TYPE", type="choice", choices=["active", "passive"], help="Specify which TYPE of scan should be performed: active|passive (performs active scanning by default)")
        parser.add_option(      "-p", "--report-path", metavar="REPORT_PATH", dest="reportpath", help="Specify alternative path for the Arachni scanner's output directory rather than one that would be generated automatically.")
        parser.add_option(      "-H", "--header", type="string", default='', metavar="NAME=VALUE", action='append', dest="header", help="Specify custom header. May be repeated. Must contain '=' character.")
        parser.add_option(      "-C", "--cookie", type="string", metavar="COOKIE=VALUE", action='append', dest="cookie", help="Specify custom cookie. May be repeated.")
        parser.add_option(      "-A", "--auth", type="string", metavar="LOGIN:PASS", dest="auth", help="Specify HTTP Authentication credentials.")
        parser.add_option(      "-R", "--no-report", dest="no_report", action="store_true", help="Don't generate, process and prepare final report from arachni_reproter. Disabled by default.")
        parser.add_option(      "-X", "--dont-exclude-common", dest="dont_exclude_commons", action="store_true", help="Include static assets in scanning (into scope), as well as logout links and so on")
        parser.add_option(      "-a", "--args", type="string", metavar="ARG", action='append', dest='additional_args', help="Specify additional arachni arguments. May be repeated (or use the param inside the quotes to pass multiple ones)")

        login = OptionGroup(parser, "Login options (autologin plugin)")
        login.add_option(       "-l", "--login", dest="plugin_login", type="choice", choices=['auto', 'script', 'js', 'browser'], metavar="type", help="Use login facilities in order to leverage authorization in tested application. For TYPE specify either 'auto' for autologin plugin, 'script' (which will auto-generate suitable script performing authentication), 'js' for javascript code, or 'browser' for PhantomJS based authentication.")
        login.add_option(       "", "--login-url", dest="plugin_login_url", metavar="URL", type="string", help="Login's form relative URL")
        login.add_option(       "", "--login-params", dest="plugin_login_params", metavar="PARAMS", type="string", help="Login's form PARAMS used to perform actual login")
        login.add_option(       "", "--login-logout", dest="plugin_login_logout", metavar="URL", type="string", default=DEFAULT_LOGOUT_PATTERN, help="Login's logout relative URL to be excluded from scope")
        login.add_option(       "", "--login-valid-check", dest="plugin_login_valid_check", default=DEFAULT_LOGIN_CHECK_PATTERN, metavar="PATTERN", type="string", help="When in --login-valid=check was used, it is needed to supply specific PATTERN which will be used in session validity checking. If empty, the login-logout pattern will be used.")
        login.add_option(       "", "--valid-session-url", dest="plugin_login_valid_session_url", default="", metavar="URL", type="string", help="When in --login-valid=session was used, it is needed to supply specific URL which will be used in session validity checking. If empty, login url will be used.")
        login.add_option(       "", "--valid-session-pattern", dest="plugin_login_valid_session_pattern", default="", metavar="PATTERN", type="string", help="When in --valid-session-rul was used, it is needed to supply specific PATTERN which will be used in session validity checking. If empty, the login-logout pattern will be used.")
        parser.add_option_group(login)

        proxy = OptionGroup(parser, "Proxy options")
        proxy.add_option(       "-x", "--proxy", dest="plugin_proxy", metavar="URL", help="Specifies proxy to be used in tool", type="string")
        parser.add_option_group(proxy)

        (options, args) = parser.parse_args()

        
        # Options validation

        if len(args) != 1:
                parser.error("Incorrect number of arguments.")

        if options.plugin_login:

                if not options.plugin_login_url or not options.plugin_login_params or not options.plugin_login_valid_check:
                        parser.error("You must supply url, form params and check pattern to perform login correctly.")

                else:
                        if not options.plugin_login_valid_check:
                                parser.error("No login check validation pattern was supplied!")

                if not options.plugin_login_logout:
                        print '[?] Warning: No logout exclusion pattern was supplied. Expect a big performance hit when scanning logout url.'

        if options.plugin_proxy:
                if not re.match(PROXY_REGEX, options.plugin_proxy):
                        parser.error("Invalid proxy url!")

        if options.auth and not ':' in options.auth:
                parser.error("You must supply colon with password to HTTP Authentication credentials!")

        if options.arachnipath:
            if not os.path.exists(options.arachnipath):
                parser.error("Specified Arachni path does not exist.")

        #if options.reportpath:
        #    if not os.path.exists(options.reportpath):
        #        parser.error("Specified report's path does not exist.")

        return (options, args)


def generate_login_script_data(baseurl, options, is_js):

        if is_js:
                data = '\n'
                firstname = ''
                for arg in options.plugin_login_params.split('&'):
                        name, val = arg.split('=')
                        if not firstname: firstname = name
                        data += 'document.getElementById("%s").value = "%s";\n' % (name, val)

                data += 'document.getElementById("%s").form.submit();' % firstname
                return data + '\n'

        elif options.plugin_login == 'script':
                data = '''
response = http.post( '{url}',
    parameters: {{
{params} 
        }},
    {headers}
    mode:   :sync,
    update_cookies: true
)

framework.options.session.check_url = {check_url}
framework.options.session.check_pattern = /{pattern}/
'''
                params = ''

                for arg in options.plugin_login_params.split('&'):
                        name, val = arg.split('=')
                        params += '\t"%s" => "%s", \n' % (name, val)

                params = params[:-3]
                u = baseurl + options.plugin_login_url

                if options.plugin_login_valid_session_pattern:
                        pattern = options.plugin_login_valid_session_pattern
                elif options.plugin_login_valid_check:
                        pattern = options.plugin_login_valid_check
                else:
                        pattern = DEFAULT_LOGOUT_PATTERN

                if options.plugin_login_valid_session_url:
                        check_url = '"' + baseurl + options.plugin_login_valid_session_url + '"'
                else:
                        # Redirection check url
                        check_url = 'to_absolute( response.headers.location, response.url )'

                hdrs = ''
                if len(options.header) > 0:
                    hdrs = 'headers: {\n'
                    for h in options.header:
                        hdrs += '\t"%s" => "%s", \n' % (h.split('=')[0], ''.join(h.split('=')[1:]))

                    hdrs = hdrs[:-3]
                    hdrs += '\n\t},'

                return data.format(url=u, params=params, headers=hdrs, check_url=check_url, pattern=pattern)

        elif options.plugin_login == 'browser':

                data = '''
browser.goto '{url}'
form = browser.form(:method => "post")
{params} 

form.submit

framework.options.session.check_url = {check_url}
framework.options.session.check_pattern = /{pattern}/
'''
                
                params = ''

                for arg in options.plugin_login_params.split('&'):
                        name, val = arg.split('=')
                        params += "form.text_field( name: '%s' ).set '%s'\n" % (name, val)

                u = baseurl + options.plugin_login_url

                if options.plugin_login_valid_session_pattern:
                        pattern = options.plugin_login_valid_session_pattern
                elif options.plugin_login_valid_check:
                        pattern = options.plugin_login_valid_check
                else:
                        pattern = DEFAULT_LOGOUT_PATTERN

                if options.plugin_login_valid_session_url:
                        check_url = '"' + baseurl + options.plugin_login_valid_session_url + '"'
                else:
                        # Redirection check url
                        check_url = 'to_absolute( response.headers.location, response.url )'
        
                return data.format(url=u, params=params, check_url=check_url, pattern=pattern)

        else:
            assert("Failed interpreting login script type.")

def build_command(options, args):
        
        cmd = []
        temp_file_name = None
        url = args[0]
        if url[-1] == '/':
                url = url[:-1]

        # Login facility
        if options.plugin_login:
                if options.plugin_login_valid_session_url:

                        if options.plugin_login_valid_session_pattern:
                                p = options.plugin_login_valid_session_pattern
                        else:
                                p = options.plugin_login_valid_check

                        cmd.append('--session-check-url="%s" --session-check-pattern="%s"' \
                                % (options.plugin_login_valid_session_url, p))

                if options.plugin_login_logout:
                        cmd.append('--scope-exclude-pattern="%s"' % options.plugin_login_logout)
                else:
                        if not options.dont_exclude_commons:
                                cmd.append('--scope-exclude-pattern="%s"' % DEFAULT_LOGOUT_PATTERN)

                if options.plugin_login == 'auto':
                        cmd.append('--plugin=autologin:url="%s",parameters="%s",check="%s"' \
                                % (url + options.plugin_login_url, options.plugin_login_params, options.plugin_login_valid_check))

                elif options.plugin_login == 'script' or options.plugin_login == 'js' or options.plugin_login == 'browser':
                        is_js = options.plugin_login == 'js'
                        if is_js:
                                f = tempfile.NamedTemporaryFile(delete=False, suffix='.js')
                        else:
                                f = tempfile.NamedTemporaryFile(delete=False)
                                
                        temp_file_name = f.name
                        f.write(generate_login_script_data(url, options, is_js))
                        f.close()

                        cmd.append('--plugin=login_script:script="' + temp_file_name + '"')


        if options.plugin_proxy:
                proxy = ''
                m = re.match(PROXY_REGEX, options.plugin_proxy)
                
                if m:
                #       proxy = 'bind_address=%s,port=%s' % (m.group(1), m.group(2))
                #       cmd.append('--plugin=proxy:' + proxy)
                        cmd.append('--http-proxy %s:%s' % (m.group(1), m.group(2)))

        if options.verbose:
                cmd.append('--output-verbose')
                cmd.append('--output-debug 4')
        else:
                cmd.append('--output-only-positives')

        if options.auth:
                creds = options.auth.split(':')
                cmd.append('--http-authentication-username="%s" --http-authentication-password="%s"' % (creds[0], creds[1]))

        if options.header:
                for i, opt in enumerate(options.header):
                        cmd.append('--http-request-header="' + opt + '"')

        if options.additional_args:
                for i, opt in enumerate(options.additional_args):
                        cmd.append(opt)

        if options.cookie:
                for i, opt in enumerate(options.cookie):
                        cmd.append('--http-cookie-string="' + opt + '"')

        if not options.dont_exclude_commons:
                cmd.append('--scope-exclude-file-extensions ' + EXCLUDED_COMMON_EXTENSIONS)
                cmd.append('--scope-exclude-binaries')
                cmd.append('--scope-auto-redundant=4')

        cmd.append('--audit-links --audit-forms --audit-cookies --audit-headers')
        cmd.append('--http-user-agent "' + DEFAULT_USER_AGENT + '"')
        cmd.append('--browser-cluster-ignore-images')

        # Exclude backup files/directories scanning (as it gets too long in completing)
        cmd.append('--checks=*,-backup_files,-backup_directories')

        # Additional plugins
        cmd.append('--plugin=metrics')
        cmd.append('--plugin=waf_detector')
        cmd.append('--plugin=discovery')
        #cmd.append('--plugin=autothrottle')
        #cmd.append('--plugin=uncommon_headers')

        m = re.match(HOST_TO_DIR_REGEX, url)
        path = ''
        if m:
                outdir = m.group(2).replace(':', '').replace('@', '')
                if m.group(3):
                        outdir += m.group(3)
                        cmd.append('--scope-include-pattern="%s"' % m.group(3))

                if options.reportpath and len(options.reportpath) > 0:
                    path = options.reportpath
                else:
                    path = join(join(DEFAULT_WORK_PATH, outdir), '/')
                    if '/www.' in path:
                        path = path.replace('/www.', '/')

                cmd.append('--report-save-path="%s" --snapshot-save-path="%s"' % (path, path))

        # Add some additional tools supporting the scan.
        #cmd.append('--plugin=exec:during="nikto -host __URL_HOST__ -port __URL_PORT__ -output \'' + path + 'nikto.log\'"')

        return (' '.join(cmd), path, temp_file_name)


def main(argv):

        (options, args) = parse_options()
        (command, path, temp_file_name) = build_command(options, args)
        try:
                command = command.strip()

                if options.arachnipath:
                    arachni_path = options.arachnipath
                else:
                    arachni_path = commands.getstatusoutput('which arachni')[1].strip()
                    if not arachni_path:
                            arachni_path = 'arachni'

                url = args[0]
                if not url.startswith('http://') and not url.startswith('https://'):
                    url = 'http://' + url

                if '/www.' in path:
                    path = path.replace('/www.', '/')

                execute = "%s %s %s" % (arachni_path, command, url)

                print '\n\t== Arachni scanner launcher, v:' + SCRIPT_VERSION + ' =='
                print '\tMariusz B., mgeeky 2015-16\n'
                print "Requested command:"
                pretty_output = " \\\n\t".join(textwrap.wrap('$ '+execute, break_long_words=False, break_on_hyphens=False))
                print "\n", pretty_output, '\n'

                if os.path.isdir(path): 
                        c = " (dir exists)" 
                else:
                        c = "(dir to be created)"
                print '\nDirectory for the output files: "%s" %s' % (path, c)

                if temp_file_name != None:
                        print 'Temporarily created authorization script file:\n' + '-'*30 + open(temp_file_name, 'r').read() + '-'*30 + '\n'

                choice = raw_input("Do you want to proceed [Y/n]: ")
                if not choice or choice.lower() == 'y':
                        print '\nHere we go...\n'
                        if not 'exists' in c:
                            try:
                                os.makedirs(path)
                            except:
                                print "[!] Could not create report's directory! You will have to create it yourself."
                                return False
                        os.system(execute)

                        if not options.no_report:
                            try:
                                report_path = max(glob.iglob(join(path, '*.afr')), key=os.path.getctime)
                                try: 
                                    os.makedirs(join(path, "reports"))
                                except:
                                    pass

                                report_zip = join(path, "reports/last_report.html.zip")
                                report_zip_out = join(path, "reports/last_report/")
                                report_cmd = "%s_reporter '%s' --reporter=html:outfile=%s" % (arachni_path, report_path, report_zip)

                                print '\n\n\t== GENERATING FINAL REPORT ==\n\n'
                                os.system(report_cmd)

                                if os.path.isfile(report_zip):
                                    # Unzip resulted report file.
                                    with zipfile.ZipFile(report_zip, 'r') as z:
                                        z.extractall(report_zip_out)

                                    if os.path.isfile(report_zip_out + "index.html"):
                                        print "\nreport can be obtained from:\n\n\t$ firefox %s &\n" % (report_zip_out + "index.html")
                            except Exception as e:
                                print "Couldn't generate final report automatically. You'll have to do this yourself."
                                print "[!] %s" % e

                else:
                    c = ["Such a shame...", "Coward, don't you want to hack this url???", "Oh, come on - launch me straightaway!"]
                    print '\n%s\n' % random.choice(c)

                print

        except:
                import traceback
                traceback.print_exc(file=sys.stdout)

        finally:
                if temp_file_name != None:
                        print 'Removing temporary script file: "%s"...' % temp_file_name
                        os.unlink(temp_file_name)

if __name__ == '__main__':
        main(sys.argv)

