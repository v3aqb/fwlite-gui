
import os
import sys
import copy
import json
import base64
import operator
import subprocess
import traceback
import configparser
from collections import deque

import urllib.request
import urllib.parse

import chardet

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QSpacerItem, QSizePolicy
from PyQt5.QtCore import QProcess

from .ui_mainwindow import Ui_MainWindow
from .systray import SystemTrayIcon, setIEproxy
from .translate import translate
_tr = translate

proxy_handler = urllib.request.ProxyHandler({})
opener = urllib.request.build_opener(proxy_handler)
urlopen = opener.open

SUPPORTED_PLUGIN = ['', 'goquiet', 'kcptun', 'simple-obfs']
SUPPORTED_PROTOCOL = ['shadowsocks', 'hxsocks2', 'http', 'socks5']


class MainWindow(QMainWindow):
    def __init__(self, path_to_conf, parent=None):
        super().__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        icon = QIcon(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.png'))
        self.setWindowIcon(icon)

        self.path_to_conf = path_to_conf
        self.path_to_local = os.path.join(os.path.dirname(os.path.abspath(self.path_to_conf)),
                                          'local.txt')

        self.conf = configparser.ConfigParser(interpolation=None)
        self.conf.optionxform = str
        self.conf.read(self.path_to_conf)
        listen = self.conf['FWLite'].get('listen', '8118')
        self.port = int(listen) if listen.isdigit() else int(listen.split(':')[1])

        self.tray = SystemTrayIcon(icon, self)
        self.tray.show()
        self.consoleText = deque(maxlen=300)
        self.runner = QProcess(self)

        # local rules
        self.ui.AddLocalRuleButton.clicked.connect(self.addLocalRule)
        self.spacer_LR = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.ui.LocalRulesLayout.addItem(self.spacer_LR)
        self.local_rule_list = []

        # redir rules
        self.ui.AddRedirectorRuleButton.clicked.connect(self.addRedirRule)
        self.spacer_RR = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.ui.RedirectorRulesLayout.addItem(self.spacer_RR)
        self.redir_rule_list = []

        # proxyList
        self.ui.proxyAddButton.clicked.connect(self.addProxy)
        self.ui.proxyRemoveButton.clicked.connect(self.delProxy)
        self.ui.protocolBox.currentIndexChanged.connect(self.protocolChanged)
        self.ui.proxyDisableButton.clicked.connect(self.disableProxy)
        self.ui.proxyActivateButton.clicked.connect(self.activateProxy)
        self.ui.exclusiveProxyAddButton.clicked.connect(self.exclusiveProxyAdd)
        header = [_tr("MainWindow", "name"),
                  _tr("MainWindow", "address"),
                  _tr("MainWindow", "priority"),
                  _tr("MainWindow", "resp"),
                  ]
        data = []
        self.PL_table_model = MyTableModel(self, data, header)

        self.ui.proxyListView.setModel(self.PL_table_model)
        self.ui.proxyListView.clicked.connect(self.on_proxy_select)
        import hxcrypto
        method_list = ['']
        method_list.extend(sorted(hxcrypto.method_supported.keys()))
        self.ui.encryptionBox.addItems(method_list)

        self.ui.pluginBox.addItems(SUPPORTED_PLUGIN)
        self.ui.protocolBox.addItems(SUPPORTED_PROTOCOL)

        # port forward
        self.ui.PFAddButton.clicked.connect(self.addForward)
        self.ui.PFRemoveButton.clicked.connect(self.delForward)
        header = [_tr("MainWindow", "target"),
                  _tr("MainWindow", "proxy"),
                  _tr("MainWindow", "port"),
                  ]
        data = []
        self.PF_table_model = MyTableModel(self, data, header)
        self.ui.PFView.setModel(self.PF_table_model)

        # settings
        self.ui.gfwlistToggle.stateChanged.connect(self.gfwlistToggle)
        self.ui.adblockToggle.stateChanged.connect(self.adblockToggle)
        self.ui.editConfButton.clicked.connect(self.openconf)
        self.ui.editLocalButton.clicked.connect(self.openlocal)

        self.createProcess()

    def addForward(self):
        try:
            target = self.ui.PFTargetEdit.text()
            port = self.ui.PFPortEdit.text()
            if not port.isdigit():
                port = 0
            port = int(port)
            proxy = self.ui.PFProxyBox.currentText()
            data = json.dumps((target, proxy, port)).encode()
            urlopen('http://127.0.0.1:%d/api/forward' % self.port, data, timeout=1).read()
            self.ui.PFTargetEdit.clear()
            self.ui.PFPortEdit.clear()
        except Exception as e:
            print(repr(e))
            print(traceback.format_exc())

    def delForward(self):
        index = self.ui.PFView.currentIndex().row()
        from http.client import HTTPConnection
        try:
            port = self.PF_table_model.mylist[index][2]
            conn = HTTPConnection('127.0.0.1', self.port, timeout=1)
            conn.request('DELETE', '/api/forward/%s' % port)
            resp = conn.getresponse()
            resp.read()
        except Exception as e:
            print(repr(e))
            print(traceback.format_exc())

    def refresh_forwardList(self):
        try:
            data = json.loads(urlopen('http://127.0.0.1:%d/api/forward' % self.port, timeout=1).read().decode())
            self.PF_table_model.update(data)
            self.ui.PFView.resizeRowsToContents()
            self.ui.PFView.resizeColumnsToContents()
        except Exception as e:
            print(repr(e))
            print(traceback.format_exc())

    def refresh_proxyList(self):
        try:
            data = json.loads(urlopen('http://127.0.0.1:%d/api/proxy' % self.port, timeout=1).read().decode())
            self.PL_table_model.update(data)
            self.ui.proxyListView.resizeRowsToContents()
            self.ui.proxyListView.resizeColumnsToContents()
            # update PFProxyBox
            self.ui.PFProxyBox.clear()
            proxy_list = [item[0] for item in data]
            self.ui.PFProxyBox.addItems(proxy_list)
        except Exception as e:
            print(repr(e))
            print(traceback.format_exc())

    def refresh_Settings(self):
        try:
            self.ui.gfwlistToggle.setCheckState(QtCore.Qt.Checked if json.loads(urlopen('http://127.0.0.1:%d/api/gfwlist' % self.port, timeout=1).read().decode()) else QtCore.Qt.Unchecked)
            self.ui.adblockToggle.setCheckState(QtCore.Qt.Checked if json.loads(urlopen('http://127.0.0.1:%d/api/adblock' % self.port, timeout=1).read().decode()) else QtCore.Qt.Unchecked)
        except Exception as e:
            print(repr(e))
            print(traceback.format_exc())

    def exclusiveProxyAdd(self):
        name = self.ui.nameEdit.text()
        self.addProxy()
        # disable all other proxy
        name_list = [item[0] for item in self.PL_table_model.mylist]
        for _name in name_list:
            if _name == name:
                continue
            self.load_proxy_by_name(_name)
            self.ui.priorityEdit.setText(str(-1))
            self.addProxy()

    def addProxy(self):
        protocol = self.ui.protocolBox.currentText()
        name = self.ui.nameEdit.text()
        hostname = self.ui.hostnameEdit.text()
        port = self.ui.portEdit.text()
        encryption = self.ui.encryptionBox.currentText()
        psk = self.ui.pskEdit.text()
        priority = self.ui.priorityEdit.text()
        username = self.ui.usernameEdit.text()
        password = self.ui.passwordEdit.text()
        plugin = self.ui.pluginBox.currentText()
        plugin_opt = self.ui.plugin_optEdit.text()
        via = self.ui.viaEdit.text()

        if not port.isdigit():
            return

        if protocol == 'shadowsocks':
            protocol = 'ss'
        elif protocol == 'hxsocks2':
            protocol = 'hxs2'

        if not name:
            name = '%s-%s' % (hostname, port)
        if not priority:
            priority = 99

        # if not all([hostname, port.isdigit(), encryption, psk]):
        #     self.tray.showMessage_(_tr("MainWindow", "error_notice"))
        #     return

        qs = {}
        urlquote = urllib.parse.quote
        if protocol == 'ss':
            userinfo = '%s:%s' % (encryption, psk)
            userinfo = base64.b64encode(userinfo.encode()).decode()
            url = 'ss://%s@%s:%s/' % (userinfo, hostname, port)
        else:
            if username:
                url = '%s://%s:%s@%s:%s/' % (protocol, username, urlquote(password), hostname, port)
            else:
                url = '%s://%s:%s/' % (protocol, hostname, port)
            if protocol == 'hxs2':
                qs['PSK'] = urlquote(psk)
                qs['method'] = encryption
        if plugin:
            qs['plugin'] = urlquote(plugin + ';' + plugin_opt)

        if qs:
            query_string = '&'.join(['%s=%s' % (k, v) for k, v in qs.items()])
            url += '?' + query_string

        if via:
            url += '|'
            url += via

        url += ' %s' % priority
        data = json.dumps((name, url)).encode()
        try:
            urlopen('http://127.0.0.1:%d/api/proxy' % self.port, data, timeout=1).read()
        except Exception:
            self.tray.showMessage_('add proxy %s failed!' % name)
        else:
            self.ui.nameEdit.clear()
            self.ui.hostnameEdit.clear()
            self.ui.portEdit.clear()
            self.ui.pskEdit.clear()
            self.ui.usernameEdit.clear()
            self.ui.passwordEdit.clear()
            self.ui.plugin_optEdit.clear()
            self.ui.priorityEdit.clear()
            self.ui.viaEdit.clear()

    def protocolChanged(self):
        ps = self.ui.protocolBox.currentText()
        self.ui.usernameEdit.setEnabled(ps != 'shadowsocks')
        self.ui.passwordEdit.setEnabled(ps != 'shadowsocks')
        self.ui.encryptionBox.setEnabled(ps in ('shadowsocks', 'hxsocks2'))
        self.ui.pskEdit.setEnabled(ps in ('shadowsocks', 'hxsocks2'))

    def activateProxy(self):
        index = self.ui.proxyListView.currentIndex().row()
        piority = self.PL_table_model.mylist[index][2]
        if 0 <= piority <= 100:
            return
        self.on_proxy_select()
        self.ui.priorityEdit.setText(str(99))
        self.addProxy()

    def disableProxy(self):
        self.on_proxy_select()
        self.ui.priorityEdit.setText(str(-1))
        self.addProxy()

    def delProxy(self):
        index = self.ui.proxyListView.currentIndex().row()
        from http.client import HTTPConnection
        try:
            name = self.PL_table_model.mylist[index][0]
            name = base64.urlsafe_b64encode(name.encode()).decode()
            conn = HTTPConnection('127.0.0.1', self.port, timeout=1)
            conn.request('DELETE', '/api/proxy/%s' % name)
            resp = conn.getresponse()
            resp.read()
        except Exception as e:
            print(repr(e))

    def on_proxy_select(self):
        index = self.ui.proxyListView.currentIndex().row()
        name = self.PL_table_model.mylist[index][0]
        piority = self.PL_table_model.mylist[index][2]
        self.load_proxy_by_name(name)
        self.ui.priorityEdit.setText(str(piority))

    def load_proxy_by_name(self, name):
        _name = base64.urlsafe_b64encode(name.encode()).decode()
        try:
            proxy = urlopen('http://127.0.0.1:%d/api/proxy/%s' % (self.port, _name), timeout=1).read().decode()
        except Exception:
            return
        if '|' in proxy:
            proxy_list = proxy.split('|')
            proxy = proxy_list[0]
            via = '|'.join(proxy_list[1:])
        else:
            via = ''

        parse = urllib.parse.urlparse(proxy)
        query = urllib.parse.parse_qs(parse.query)

        import hxcrypto
        method_list = sorted(hxcrypto.method_supported.keys())
        if parse.scheme == 'ss':
            self.ui.protocolBox.setCurrentIndex(SUPPORTED_PROTOCOL.index('shadowsocks'))
            method = parse.username
            password = parse.password
            if not password:
                method, password = base64.b64decode(method).decode().split(':', 1)
            method_index = method_list.index(method) + 1
            self.ui.encryptionBox.setCurrentIndex(method_index)
            self.ui.pskEdit.setText(password)
            self.ui.usernameEdit.setText('')
            self.ui.passwordEdit.setText('')
        elif parse.scheme == 'hxs2':
            self.ui.protocolBox.setCurrentIndex(SUPPORTED_PROTOCOL.index('hxsocks2'))
            method = query.get('method', ['aes-128-cfb'])[0].lower()
            method_index = method_list.index(method) + 1
            self.ui.encryptionBox.setCurrentIndex(method_index)
            psk = query.get('PSK', [''])[0]
            self.ui.pskEdit.setText(psk)
            self.ui.usernameEdit.setText(parse.username)
            self.ui.passwordEdit.setText(parse.password)
        else:
            # socks5 and http
            self.ui.protocolBox.setCurrentIndex(SUPPORTED_PROTOCOL.index(parse.scheme) if parse.scheme else 2)
            self.ui.encryptionBox.setCurrentIndex(0)
            self.ui.pskEdit.setText('')
            self.ui.usernameEdit.setText(parse.username)
            self.ui.passwordEdit.setText(parse.password)

        self.ui.nameEdit.setText(name)
        self.ui.hostnameEdit.setText(parse.hostname)
        self.ui.portEdit.setText(str(parse.port))
        self.ui.viaEdit.setText(via)

        # plugin
        plugin = query.get('plugin', [None, ])[0]
        plugin_info = plugin.split(';') if plugin else None

        self.ui.pluginBox.setCurrentIndex(SUPPORTED_PLUGIN.index(plugin) if plugin else 0)
        if plugin_info:
            self.ui.plugin_optEdit.setText(';'.join(plugin_info[1:]))

    def gfwlistToggle(self):
        try:
            urlopen('http://127.0.0.1:%d/api/gfwlist' % self.port, json.dumps(self.ui.gfwlistToggle.isChecked()).encode(), timeout=1).read()
        except Exception as e:
            print(repr(e))

    def adblockToggle(self):
        try:
            urlopen('http://127.0.0.1:%d/api/gfwlist' % self.port, json.dumps(self.ui.adblockToggle.isChecked()).encode(), timeout=1).read()
        except Exception as e:
            print(repr(e))

    def openlocal(self):
        self.openfile(self.path_to_local)

    def openconf(self):
        self.openfile(self.path_to_conf)

    def openfile(self, path):
        if sys.platform.startswith('win'):
            cmd = 'start'
        elif sys.platform.startswith('linux'):
            cmd = 'xdg-open'
        elif sys.platform.startswith('darwin'):
            cmd = 'open'
        else:
            return self.showMessage_('OS not recognised')
        subprocess.Popen('%s %s' % (cmd, path), shell=True)
        self.tray.showMessage_(_tr("MainWindow", "reload_notice"))

    def refresh_RR(self):
        try:
            data = json.loads(urlopen('http://127.0.0.1:%d/api/redirector' % self.port, timeout=1).read().decode())
            lst = []
            self.ui.RedirectorRulesLayout.removeItem(self.spacer_RR)
            for redir_rule in data:
                rule, _, dest = redir_rule.partition(' ')
                if self.redir_rule_list:
                    w = self.redir_rule_list.pop(0)
                    w.updaterule(rule, dest)
                    w.setVisible(True)
                else:
                    w = RedirRule(rule, dest, self)
                    self.ui.RedirectorRulesLayout.addWidget(w)
                lst.append(w)
            for w in self.redir_rule_list:
                w.setVisible(False)
            self.ui.RedirectorRulesLayout.addItem(self.spacer_RR)
            self.redir_rule_list = lst
        except Exception as e:
            print(repr(e))

    def addRedirRule(self):
        rule = self.ui.RuleEdit.text()
        dest = self.ui.DestEdit.text()
        data = json.dumps((rule, dest)).encode()
        try:
            urlopen('http://127.0.0.1:%d/api/redirector' % self.port, data, timeout=1)
        except Exception:
            self.tray.showMessage_('add redirrule %s %s failed!' % (rule, dest))
        else:
            self.ui.RuleEdit.clear()
            self.ui.DestEdit.clear()

    def refresh_LR(self):
        # uri = 'http://127.0.0.1:%d/api/localrule' % self.port
        # http_request('GET', uri, cb=self._refresh_LR)
        try:
            data = json.loads(urlopen('http://127.0.0.1:%d/api/localrule' % self.port, timeout=1).read().decode())
            lst = []
            self.ui.LocalRulesLayout.removeItem(self.spacer_LR)
            for rule, exp in data:
                if self.local_rule_list:
                    w = self.local_rule_list.pop(0)
                    w.updaterule(rule, exp)
                    w.setVisible(True)
                else:
                    w = LocalRule(rule, exp, self)
                    self.ui.LocalRulesLayout.addWidget(w)
                lst.append(w)
            for w in self.local_rule_list:
                w.setVisible(False)
            self.ui.LocalRulesLayout.addItem(self.spacer_LR)
            self.local_rule_list = lst
        except Exception as e:
            print(repr(e))

    def addLocalRule(self):
        exp = int(self.ui.ExpireEdit.text()) if self.ui.ExpireEdit.text().isdigit() and int(self.ui.ExpireEdit.text()) > 0 else None
        rule = self.ui.LocalRuleEdit.text()
        data = json.dumps((rule, exp)).encode()
        try:
            urlopen('http://127.0.0.1:%d/api/localrule' % self.port, data, timeout=1).read()
        except Exception as e:
            print(repr(e))
        else:
            self.ui.LocalRuleEdit.clear()
            self.ui.ExpireEdit.clear()

    def killProcess(self):
        self.runner.readyReadStandardError.connect(lambda: None)
        self.runner.readyReadStandardOutput.connect(lambda: None)
        if self.runner.state() == QProcess.Running:
            try:
                urlopen('http://127.0.0.1:%d/api/exit' % self.port, timeout=2).read()
            except Exception as e:
                print(repr(e))
            self.runner.kill()
            self.runner.waitForFinished(100)

    def createProcess(self):
        self.killProcess()

        self.conf = configparser.ConfigParser(interpolation=None)
        self.conf.optionxform = str
        self.conf.read(self.path_to_conf)
        listen = self.conf['FWLite'].get('listen', '8118')
        port = int(listen) if listen.isdigit() else int(listen.split(':')[1])
        if port != self.port:
            self.port = port
            if sys.platform.startswith('win'):
                setIEproxy(1, u'127.0.0.1:%d' % self.port)

        if sys.platform.startswith('win'):
            # find python
            pdir = os.path.dirname(sys.executable)
            python = os.path.join(pdir, 'python.exe')
        else:
            python = sys.executable

        cmd = '"%s" -m fwlite_cli -c %s -gui' % (python, self.path_to_conf)
        self.runner.start(cmd)
        self.runner.readyReadStandardError.connect(self.newStderrInfo)
        self.runner.readyReadStandardOutput.connect(self.newStdoutInfo)

    def newStderrInfo(self):
        freload = False
        data = bytes(self.runner.readAllStandardError())
        encoding = chardet.detect(data)['encoding'].lower() if chardet.detect(data)['encoding'] else 'ascii'
        data = data.decode(encoding)
        lines = data.strip().splitlines()
        for line in copy.copy(lines):
            if 'Update Completed' in line:
                freload = True
            if "error: can't start new thread" in line:
                freload = True
            elif 'dnslib_resolve_over_' in line:
                lines.remove(line)
            elif 'extend_iplist start' in line:
                lines.remove(line)
            elif 'host to iplist' in line:
                lines.remove(line)
            elif '<DNS Question:' in line:
                lines.remove(line)
        self.consoleText.extend(lines)
        self.ui.console.setPlainText(u'\n'.join(self.consoleText))
        self.ui.console.moveCursor(QtGui.QTextCursor.End)
        if freload:
            self.reload(clear=False)

    def newStdoutInfo(self):
        data = bytes(self.runner.readAllStandardOutput())
        if not data:
            return
        data = data.decode()
        data_list = data.splitlines(keepends=False)
        if 'all' in data_list or '' in data_list:
            self.refresh_LR()
            self.refresh_RR()
            self.refresh_proxyList()
            self.refresh_forwardList()
            self.refresh_Settings()
            return
        if 'local' in data_list:
            self.refresh_LR()
        if 'redir' in data_list:
            self.refresh_RR()
        if 'proxy' in data_list:
            self.refresh_proxyList()
        if 'forward' in data_list:
            self.refresh_forwardList()
        if 'settings' in data_list:
            self.refresh_Settings()

    def showToggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.ui.tabWidget.setCurrentIndex(0)
            self.show()
            if self.isMinimized():
                self.showNormal()
            self.activateWindow()

    def openSetting(self):
        self.ui.tabWidget.setCurrentIndex(5)
        self.show()
        if self.isMinimized():
            self.showNormal()
        self.activateWindow()

    def closeEvent(self, event):
        # hide mainwindow when close
        if self.isVisible():
            self.hide()
        event.ignore()

    def reload(self, clear=True):
        if clear:
            self.ui.console.clear()
            self.consoleText.clear()
        self.createProcess()


class MyTableModel(QtCore.QAbstractTableModel):
    def __init__(self, parent, mylist, header, *args):
        QtCore.QAbstractTableModel.__init__(self, parent, *args)
        self.mylist = mylist
        self.header = header

    def rowCount(self, parent):
        return len(self.mylist)

    def columnCount(self, parent):
        return len(self.header)

    def data(self, index, role):
        if not index.isValid():
            return None
        elif role != QtCore.Qt.DisplayRole:
            return None
        try:
            return self.mylist[index.row()][index.column()]
        except IndexError:
            return None

    def update(self, mylist):
        self.layoutAboutToBeChanged.emit()
        self.mylist = mylist
        self.layoutChanged.emit()

    def headerData(self, col, orientation, role):
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self.header[col]
        return None

    def sort(self, col, order):
        """sort table by given column number col"""
        self.layoutAboutToBeChanged.emit()
        self.mylist = sorted(self.mylist, key=operator.itemgetter(col))
        if order == QtCore.Qt.DescendingOrder:
            self.mylist.reverse()
        self.layoutChanged.emit()


class LocalRule(QWidget):
    def __init__(self, rule, exp, window, parent=None):
        super(LocalRule, self).__init__(parent)
        self.resize(232, 23)
        self.horizontalLayout = QtWidgets.QHBoxLayout(self)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit = QtWidgets.QLineEdit(self)
        self.lineEdit.setReadOnly(True)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        self.copyButton = QtWidgets.QPushButton(self)
        self.copyButton.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.copyButton.setObjectName("copyButton")
        self.horizontalLayout.addWidget(self.copyButton)
        self.delButton = QtWidgets.QPushButton(self)
        self.delButton.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.delButton.setObjectName("delButton")
        self.horizontalLayout.addWidget(self.delButton)
        self.copyButton.setText(_tr("LocalRule", "Copy"))
        self.delButton.setText(_tr("LocalRule", "Delete"))

        self.delButton.clicked.connect(self.delrule)
        self.copyButton.clicked.connect(self.rulecopy)
        self.window = window
        self.rule = rule
        self.updaterule(rule, exp)

    def rulecopy(self):
        cb = QApplication.clipboard()
        cb.clear(mode=cb.Clipboard)
        cb.setText(self.rule, mode=cb.Clipboard)

    def delrule(self):
        from http.client import HTTPConnection
        conn = HTTPConnection('127.0.0.1', self.window.port, timeout=1)
        conn.request('DELETE', '/api/localrule/%s' % base64.urlsafe_b64encode(self.rule.encode()).decode())
        conn.getresponse().read()

    def updaterule(self, rule, exp):
        self.rule = rule
        self.exp = exp
        text = '%s%s' % (self.rule, (' expire in %.1fs' % exp if exp else ''))
        self.lineEdit.setText(text)


class RedirRule(QWidget):
    def __init__(self, rule, dest, window, parent=None):
        super(RedirRule, self).__init__(parent)
        self.resize(232, 23)
        self.horizontalLayout = QtWidgets.QHBoxLayout(self)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit = QtWidgets.QLineEdit(self)
        self.lineEdit.setReadOnly(True)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        self.delButton = QtWidgets.QPushButton(self)
        self.delButton.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.delButton.setObjectName("delButton")
        self.horizontalLayout.addWidget(self.delButton)
        self.delButton.setText(_tr("LocalRule", "Delete"))

        self.delButton.clicked.connect(self.delrule)

        self.window = window
        self.rule = '%s %s' % (rule, dest)
        self.updaterule(rule, dest)

    def delrule(self):
        from http.client import HTTPConnection
        conn = HTTPConnection('127.0.0.1', self.window.port, timeout=1)
        conn.request('DELETE', '/api/redirector/?rule=%s' % (base64.urlsafe_b64encode(self.rule.encode()).decode()))
        conn.getresponse().read()

    def updaterule(self, rule, dest):
        self.rule = '%s %s' % (rule, dest)
        self.lineEdit.setText(self.rule)


if __name__ == '__main__':
    if os.name == 'nt':
        import ctypes
        myappid = 'v3aqb.fwlite'  # arbitrary string
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    app = QApplication([])
    ex = MainWindow(sys.argv)
    sys.exit(app.exec_())
