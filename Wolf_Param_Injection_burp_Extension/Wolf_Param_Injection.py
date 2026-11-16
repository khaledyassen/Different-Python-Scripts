#!/usr/bin/env python
# -*- coding: utf-8 -*-

from burp import ITab
from burp import IBurpExtender
from burp import IHttpListener
from burp import IContextMenuFactory
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from burp import IHttpRequestResponseWithMarkers
from burp import IHttpService
from burp import ITextEditor
from javax.swing import JList
from javax.swing import JTable
from javax.swing import JFrame
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JToggleButton
from javax.swing import JCheckBox
from javax.swing import JMenuItem
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing.tree import TreePath
from javax.swing import JPopupMenu
from javax.swing import JSplitPane
from javax.swing import JEditorPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from javax.swing.table import TableRowSorter
from javax.swing.table import AbstractTableModel
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import DefaultTreeCellRenderer
from javax.swing.tree import DefaultTreeModel
from javax.swing.text.html import HTMLEditorKit
from threading import Lock
from java.io import File
from java.net import URL
from java.net import URLEncoder
from java.awt import Color
from java.awt import Dimension
from java.awt import BorderLayout
from java.awt.event import MouseAdapter
from java.awt.event import ActionListener
from java.awt.event import AdjustmentListener
from java.util import LinkedList
from java.util import ArrayList
from java.lang import Runnable
from java.lang import Integer
from java.lang import String
from java.lang import Math
from thread import start_new_thread
from array import array
import datetime
import re

#
# ---------------------------------------------------------------------------
# VULN_DEFS drives the whole extension.  Every vulnerability class Trishul
# tests for is described once, here, instead of being hand duplicated in the
# table model, the Issues tree and the Advisory panel.  To add a brand new
# check, add an entry here and a matching "check_<key>" method on
# BurpExtender - the table column, the tree branch, the coloured cell and the
# advisory write-up all appear automatically.
#
# key          - internal identifier, also the suffix of the check_<key>()
#                detection method and the JCheckBox attribute name
# label        - column header / checkbox label
# tree         - label used for this vulnerability's branch in the Issues tree
# severity     - shown in the Advisory "Issue" table
# general      - generic explanation of the vulnerability class (like the
#                original XSS/SQLi/SSTI write ups)
# remediation  - generic remediation advice for the vulnerability class
# ---------------------------------------------------------------------------
#
VULN_DEFS = [
    {
        "key": "xss",
        "label": "XSS",
        "tree": "Cross-Site-Scripting",
        "severity": "High",
        "general": "Cross-site scripting vulnerabilities arise when data is copied from a request and echoed into the application's response in an unsafe way. An attacker can use the vulnerability to construct a request that, if issued by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.<br><br>The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.<br><br>The security impact of cross-site scripting vulnerabilities is dependent upon the nature of the vulnerable application, the kinds of data and functionality that it contains, and the other applications that belong to the same domain and organization.",
        "remediation": "In most situations where user-controllable data is copied into application responses, cross-site scripting attacks can be prevented using two layers of defenses:<br><br>1. Input should be validated as strictly as possible on arrival, given the kind of content that it is expected to contain. Input which fails validation should be rejected, not sanitized.<br>2. User input should be HTML-encoded at any point where it is copied into application responses. All HTML metacharacters, including &lt; &gt; \" ' and =, should be replaced with the corresponding HTML entities."
    },
    {
        "key": "sqli",
        "label": "SQLi",
        "tree": "SQL-Injection",
        "severity": "High",
        "general": "SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.<br>A wide range of damaging attacks can often be delivered via SQL injection, including reading or modifying critical application data, interfering with application logic, escalating privileges within the database and taking control of the database server.",
        "remediation": "The most effective way to prevent SQL injection attacks is to use parameterized queries (also known as prepared statements) for all database access, so that the structure of the query is fixed before any item of user input is incorporated into it. Stored procedures and quote-doubling are not reliable substitutes for parameterized queries."
    },
    {
        "key": "ssti",
        "label": "SSTI",
        "tree": "Server-Side-Template-Injection",
        "severity": "High",
        "general": "Web applications commonly use template engines such as Smarty, Mako, Twig, Freemarker and Jinja2 to present dynamic data on web pages and in emails. This feature allows embedding user input into the web application, and if not sanitized properly, could make it vulnerable to Server-Side Template Injection and potentially give remote code execution (RCE) capability to intruders.",
        "remediation": "Remediations differ between template engines, but the following concepts help across all of them:<br>1. <b>Sanitization:</b> never pass raw, un-sanitized user input into a template as if it were trusted template source; only ever pass it in as a plain data value.<br>2. <b>Sandboxing:</b> if the business logic requires rendering of user-supplied template syntax, do so inside a sandboxed template engine / sandboxed environment (such as a locked-down container)."
    },
    {
        "key": "crlf",
        "label": "CRLF Injection",
        "tree": "CRLF-Injection",
        "severity": "Medium",
        "general": "CRLF (Carriage Return Line Feed) injection vulnerabilities arise when user input containing unescaped \\r\\n sequences is placed into an HTTP response header, a log file, or another line-oriented structure. If an attacker can inject a CRLF sequence followed by their own header, they can split the response into two, inject arbitrary response headers, perform HTTP response splitting, poison a cache, smuggle an additional response, or (depending on the application) inject arbitrary cookies or perform reflected XSS by terminating the header section and writing their own HTML body.",
        "remediation": "Never place user-controllable data directly into a response header, redirect Location, or Set-Cookie value without first stripping or encoding CR (%0D) and LF (%0A) characters. Use framework APIs for setting headers/cookies/redirects rather than concatenating raw strings, since most modern frameworks reject embedded CR/LF by default."
    },
    {
        "key": "ssrf",
        "label": "SSRF",
        "tree": "Server-Side-Request-Forgery",
        "severity": "High",
        "general": "Server-Side Request Forgery (SSRF) vulnerabilities arise when an application can be induced to make an HTTP (or other protocol) request to a destination of the attacker's choosing, using the server itself as the origin of the request. This can be used to reach internal-only services, cloud metadata endpoints (for example to steal temporary IAM credentials), or to port-scan the internal network from a trusted network position.",
        "remediation": "Validate and, where possible, allow-list destination hosts/URLs supplied by users rather than block-listing. Disable unused URL schemes and redirects in whatever HTTP client library is used server-side, block requests to loopback, link-local (169.254.0.0/16) and other private address ranges at the network layer, and avoid ever returning the raw response body of a server-side request directly to the user."
    },
    {
        "key": "openredirect",
        "label": "Open Redirect",
        "tree": "Open-Redirect",
        "severity": "Medium",
        "general": "Open redirect vulnerabilities arise when an application accepts a user-controllable value (commonly a 'redirect', 'next', 'url', 'return' or similar parameter) and uses it, without validation, as the destination of an HTTP redirect (a 3xx response with a Location header) or a client-side redirect (a meta-refresh tag or a JavaScript window.location/location.href assignment). An attacker can craft a link into the vulnerable application that silently forwards victims on to an attacker-controlled site, which is frequently used to lend credibility to phishing attacks, to bypass referer- or domain-based access checks, or, in OAuth/SSO flows, to steal tokens or authorization codes.",
        "remediation": "Avoid placing user-controllable input directly into a redirect destination. Where redirecting to a user-supplied target is a genuine business requirement, validate the destination against a server-side allow-list of permitted paths or hosts (never a block-list), reject any absolute or protocol-relative URL (//host/path) that points off-site, and consider showing an interstitial warning page before redirecting to any value that was not generated by the server itself."
    },
    {
        "key": "xxe",
        "label": "XXE",
        "tree": "XML-External-Entity",
        "severity": "High",
        "general": "XML External Entity (XXE) injection vulnerabilities arise when an application parses attacker-supplied XML without disabling the resolution of external entities. An attacker can define a custom external entity using a URL such as a local file:// path, and reference it from within the document being parsed, causing the parser to read and disclose the contents of that file (or to make outbound network requests, leading to SSRF).",
        "remediation": "Disable DTD processing and external entity resolution entirely in the XML parser being used (most parsers provide a flag for this, e.g. setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) for a SAX/DOM parser in Java). Prefer a data format that does not support entities (such as JSON) wherever the application's XML support is not strictly required."
    },
    {
        "key": "oscmd",
        "label": "OS Command Injection",
        "tree": "OS-Command-Injection",
        "severity": "Critical",
        "general": "OS command injection vulnerabilities arise when an application incorporates user-controllable data into a command that is passed to the operating system shell. If the data is not strictly validated, an attacker can use shell metacharacters (such as ; | & ` $( ) ) to modify the command that is executed, and so execute arbitrary commands on the host with the privileges of the vulnerable application.",
        "remediation": "Avoid passing user input to operating system shells entirely; use language/library APIs that invoke the target functionality directly (for example a native library call) instead of shelling out. Where a command must be built dynamically, use an API that supports passing a list of discrete arguments rather than a single concatenated command string, and strictly validate (allow-list) any value that is incorporated into the command."
    },
    {
        "key": "lfi",
        "label": "LFI/LFD",
        "tree": "Local-File-Inclusion",
        "severity": "High",
        "general": "Local File Inclusion / Local File Disclosure vulnerabilities arise when user-controllable input is used, without sufficient validation, to build a filesystem path that the application then reads or includes. Using directory traversal sequences (../) or absolute paths, an attacker can often read arbitrary files on the server (configuration files, source code, credentials) or, in the case of inclusion rather than simple disclosure, achieve remote code execution.",
        "remediation": "Avoid passing user input into filesystem APIs at all where possible. Where a filename or path fragment must be accepted from the user, resolve it to an absolute canonical path and verify that the result still lives inside an expected base directory (reject the request otherwise), and prefer looking the input up as a key into a fixed allow-list of known-safe files rather than building a path directly from it."
    }
]

VULN_KEYS = [v["key"] for v in VULN_DEFS]

#
# Lightweight stand-in for a Burp IParameter, used when the request has no
# conventional GET/POST/JSON parameters at all - either a bare XML body, or
# any other raw body (plain text, a PUT/PATCH payload, etc). It only needs
# to support the handful of methods the rest of Trishul calls on a
# "parameter" object. ptype is -1 for a bare-XML body (handled only by the
# XXE check) and -2 for any other raw body (handled by every other check).
#
class PseudoParameter:
    def __init__(self, name, ptype=-1):
        self._name = name
        self._ptype = ptype

    def getName(self):
        return self._name

    def getType(self):
        return self._ptype

    def getValue(self):
        return ""


#
# Initialize BurpExtender API to use Extender features
#

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory, IHttpRequestResponseWithMarkers, ITextEditor):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        # Initialize callbacks to be used later

        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Wolf_Param_Injection")

        self._log = ArrayList()
        # _log used to store our outputs for a URL, which is retrieved later by the tool

        self._lock = Lock()
        # Lock is used for locking threads while updating logs in order such that no multiple updates happen at once

        self.intercept = 0

        self.FOUND = "Found"
        self.CHECK = "Possible! Check Manually"
        self.NOT_FOUND = "Not Found"
        # Static Values for output

        # Initialize GUI
        self.issuesTab()

        self.advisoryReqResp()

        self.configTab()

        self.tabsInit()

        self.definecallbacks()

        print("Thank You for Installing Wolf_Param_Injection")

        return

    #
    # Initialize Issues Tab displaying the JTree
    #
    def issuesTab(self):
        self.root = DefaultMutableTreeNode('Issues')

        frame = JFrame("Issues Tree")

        self.tree = JTree(self.root)
        self.rowSelected = ''
        self.tree.addMouseListener(mouseclick(self))
        self.issuepanel = JScrollPane()
        self.issuepanel.setPreferredSize(Dimension(300, 450))
        self.issuepanel.getViewport().setView((self.tree))
        frame.add(self.issuepanel, BorderLayout.CENTER)

    #
    # Adding Issues to Issues TreePath
    #
    def addIssues(self, branch, branchData=None):
        if branchData == None:
            branch.add(DefaultMutableTreeNode('No valid data'))
        else:
            for item in branchData:
                branch.add(DefaultMutableTreeNode(item))

    #
    # Initialize the Config Tab to modify tool settings
    #
    def configTab(self):
        Config = JLabel("Config")
        self.startButton = JToggleButton("Intercept Off", actionPerformed=self.startOrStop)
        self.startButton.setBounds(40, 30, 220, 30)

        self.autoScroll = JCheckBox("Auto Scroll")
        self.autoScroll.setBounds(40, 80, 220, 30)

        # One checkbox per vulnerability class, generated from VULN_DEFS.
        # self.checkboxes["xss"], self.checkboxes["sqli"], ... etc are what
        # the rest of the extension consults to see whether a given check is
        # enabled.
        self.checkboxes = {}
        y = 110
        for vd in VULN_DEFS:
            cb = JCheckBox("Detect " + vd["label"])
            cb.setSelected(True)
            cb.setBounds(40, y, 260, 30)
            self.checkboxes[vd["key"]] = cb
            y += 30

        self.blindxss = JCheckBox("Blind XSS")
        self.blindxss.setBounds(40, y, 220, 30)
        y += 40

        self.BlindXSSText = JTextArea("", 5, 30)

        scrollbxssText = JScrollPane(self.BlindXSSText)
        scrollbxssText.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        scrollbxssText.setBounds(40, y, 400, 110)
        y += 120

        self.configtab = JPanel()
        self.configtab.setLayout(None)
        self.configtab.setBounds(0, 0, 450, y + 20)
        self.configtab.add(Config)
        self.configtab.add(self.startButton)
        self.configtab.add(self.autoScroll)
        for vd in VULN_DEFS:
            self.configtab.add(self.checkboxes[vd["key"]])
        self.configtab.add(self.blindxss)
        self.configtab.add(scrollbxssText)

    #
    # Turn Intercept from Proxy on or off
    #
    def startOrStop(self, event):
        if self.startButton.getText() == "Intercept Off":
            self.startButton.setText("Intercept On")
            self.startButton.setSelected(True)
            self.intercept = 1
        else:
            self.startButton.setText("Intercept Off")
            self.startButton.setSelected(False)
            self.intercept = 0

    #
    # Intialize the Advisory, Request and Response Tabs
    #
    def advisoryReqResp(self):
        self.textfield = JEditorPane("text/html", "")
        self.kit = HTMLEditorKit()
        self.textfield.setEditorKit(self.kit)
        self.doc = self.textfield.getDocument()
        self.textfield.setEditable(0)
        self.advisorypanel = JScrollPane()
        self.advisorypanel.getVerticalScrollBar()
        self.advisorypanel.setPreferredSize(Dimension(300, 450))
        self.advisorypanel.getViewport().setView((self.textfield))

        self.selectedreq = []

        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        self._texteditor = self._callbacks.createTextEditor()
        self._texteditor.setEditable(False)

    #
    # Initialize Trishul Tabs
    #
    def tabsInit(self):
        self.logTable = Table(self)
        tableWidth = self.logTable.getPreferredSize().width
        self.logTable.getColumn("#").setPreferredWidth(Math.round(tableWidth / 100 * 0.1))
        self.logTable.getColumn("Method").setPreferredWidth(Math.round(tableWidth / 100 * 3))
        self.logTable.getColumn("URL").setPreferredWidth(Math.round(tableWidth / 100 * 30))
        self.logTable.getColumn("Parameters").setPreferredWidth(Math.round(tableWidth / 100 * 1))
        for vd in VULN_DEFS:
            self.logTable.getColumn(vd["label"]).setPreferredWidth(Math.round(tableWidth / 100 * 6))
        self.logTable.getColumn("Request Time").setPreferredWidth(Math.round(tableWidth / 100 * 4))

        self.tableSorter = TableRowSorter(self)
        self.logTable.setRowSorter(self.tableSorter)

        self._bottomsplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._bottomsplit.setDividerLocation(460)

        self.issuetab = JTabbedPane()
        self.issuetab.addTab("Config", self.configtab)
        self.issuetab.addTab("Issues", self.issuepanel)
        self._bottomsplit.setLeftComponent(self.issuetab)

        self.tabs = JTabbedPane()
        self.tabs.addTab("Advisory", self.advisorypanel)
        self.tabs.addTab("Request", self._requestViewer.getComponent())
        self.tabs.addTab("Response", self._responseViewer.getComponent())
        self.tabs.addTab("Highlighted Response", self._texteditor.getComponent())
        self._bottomsplit.setRightComponent(self.tabs)

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setDividerLocation(450)
        self._splitpane.setResizeWeight(1)
        self.scrollPane = JScrollPane(self.logTable)
        self._splitpane.setLeftComponent(self.scrollPane)
        self.scrollPane.getVerticalScrollBar().addAdjustmentListener(autoScrollListener(self))
        self._splitpane.setRightComponent(self._bottomsplit)

    #
    # Initialize burp callbacks
    #
    def definecallbacks(self):
        self._callbacks.registerHttpListener(self)
        self._callbacks.customizeUiComponent(self._splitpane)
        self._callbacks.customizeUiComponent(self.logTable)
        self._callbacks.customizeUiComponent(self.scrollPane)
        self._callbacks.customizeUiComponent(self._bottomsplit)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.addSuiteTab(self)

    #
    # Menu Item to send Request to Trishul
    #
    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        if responses > 0:
            ret = LinkedList()
            requestMenuItem = JMenuItem("Send request to Wolf_Param_Injection")

            for response in responses:
                requestMenuItem.addActionListener(handleMenuItems(self, response, "request"))
            ret.add(requestMenuItem)
            return ret
        return None

    #
    # Highlighting Response
    #
    def markHttpMessage(self, requestResponse, responseMarkString):
        responseMarkers = None
        if responseMarkString:
            response = requestResponse.getResponse()
            responseMarkBytes = self._helpers.stringToBytes(responseMarkString)
            start = self._helpers.indexOf(response, responseMarkBytes, False, 0, len(response))
            if -1 < start:
                responseMarkers = [array('i', [start, start + len(responseMarkBytes)])]

        requestHighlights = [array('i', [0, 5])]
        return self._callbacks.applyMarkers(requestResponse, requestHighlights, responseMarkers)

    def getTabCaption(self):
        return "Wolf_Param_Injection"

    def getUiComponent(self):
        return self._splitpane

    #
    # Table Model to display URL's and results based on the log size
    #
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 4 + len(VULN_DEFS) + 1

    def getColumnName(self, columnIndex):
        data = ['#', 'Method', 'URL', 'Parameters'] + [vd["label"] for vd in VULN_DEFS] + ["Request Time"]
        try:
            return data[columnIndex]
        except IndexError:
            return ""

    def getColumnClass(self, columnIndex):
        data = [Integer, String, String, Integer] + [String for vd in VULN_DEFS] + [String]
        try:
            return data[columnIndex]
        except IndexError:
            return ""

    # Get Data stored in log and display in the respective columns
    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return rowIndex + 1
        if columnIndex == 1:
            return logEntry._method
        if columnIndex == 2:
            return logEntry._url.toString()
        if columnIndex == 3:
            return len(logEntry._parameter)
        vulnIndex = columnIndex - 4
        if 0 <= vulnIndex < len(VULN_DEFS):
            key = VULN_DEFS[vulnIndex]["key"]
            return logEntry._status[key]
        if columnIndex == 4 + len(VULN_DEFS):
            return logEntry._req_time
        return ""

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    # For Intercepted requests perform tests in scope
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInf):
        if self.intercept == 1:
            if toolFlag == self._callbacks.TOOL_PROXY:
                if not messageIsRequest:
                    requestInfo = self._helpers.analyzeRequest(messageInf)
                    requeststr = requestInfo.getUrl()
                    parameters = requestInfo.getParameters()
                    param_new = [p for p in parameters if p.getType() != 2]
                    xmlBody = self.isXmlRequest(requestInfo, messageInf.getRequest())
                    hasBody = self.hasRequestBody(requestInfo, messageInf.getRequest())
                    if len(param_new) != 0 or xmlBody or hasBody:
                        if self._callbacks.isInScope(URL(str(requeststr))):
                            start_new_thread(self.sendRequestToTrishul, (messageInf,))
        return

    #
    # Helper: does this request carry an XML body? Used to decide whether the
    # XXE check applies, including for bodies that have no conventional
    # GET/POST/JSON parameters for the other checks to run against.
    #
    def isXmlRequest(self, requestInfo, request):
        try:
            bodyOffset = requestInfo.getBodyOffset()
            body = self._helpers.bytesToString(request)[bodyOffset:].strip()
        except:
            body = ""
        if body.startswith("<?xml") or body.startswith("<"):
            return True
        for h in requestInfo.getHeaders():
            if h.lower().startswith("content-type:") and "xml" in h.lower():
                return True
        return False

    #
    # Helper: does this request carry ANY non-empty body at all, regardless
    # of HTTP method or content type? Used by the raw-body fallback so that
    # PUT/PATCH/DELETE (or any other method) requests whose body Burp cannot
    # parse into conventional GET/POST/JSON parameters still get tested.
    #
    def hasRequestBody(self, requestInfo, request):
        try:
            bodyOffset = requestInfo.getBodyOffset()
            body = self._helpers.bytesToString(request)[bodyOffset:]
        except:
            body = ""
        return len(body.strip()) > 0

    #
    # Main processing of Trishul
    #
    def sendRequestToTrishul(self, messageInfo):
        request = messageInfo.getRequest()
        req_time = datetime.datetime.today()
        requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
        messageInfo = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(requestURL.getHost()), int(requestURL.getPort()), requestURL.getProtocol() == "https"), request)
        resp_time = datetime.datetime.today()
        time_taken = (resp_time - req_time).total_seconds()
        response = messageInfo.getResponse()
        Comp_req = messageInfo
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        self.content_resp = self._helpers.analyzeResponse(response)
        requestURL = requestInfo.getUrl()
        parameters = requestInfo.getParameters()
        requeststring = self._helpers.bytesToString(request)
        headers = requestInfo.getHeaders()
        bodyIsXml = self.isXmlRequest(requestInfo, request)
        try:
            bodyOffset = requestInfo.getBodyOffset()
            bodyString = requeststring[bodyOffset:]
        except:
            bodyString = ""

        # Used to obtain GET, POST, multipart and JSON parameters from the
        # Burp API. This is intentionally method-agnostic: Burp classifies a
        # parameter by WHERE it lives (URL query string, body,
        # multipart/form-data field or JSON field), not by which HTTP verb
        # carried it, so GET, POST, PUT, PATCH and DELETE requests are all
        # picked up here as long as Burp could parse their parameters.
        #   0 = PARAM_URL, 1 = PARAM_BODY, 5 = PARAM_MULTIPART_ATTR, 6 = PARAM_JSON
        param_new = [p for p in parameters if p.getType() in (0, 1, 5, 6)]

        # Some requests (most often PUT/PATCH/DELETE with a raw, non-form,
        # non-JSON body, but this can happen with any method) have a body
        # that Burp cannot break into named parameters at all. Rather than
        # skip them, give them a single pseudo-parameter to hang results
        # off, exactly as the original Trishul already did for bare XML
        # bodies - just generalised to any raw body and to every check, not
        # only XXE.
        usingPseudoParam = False
        pseudoKind = None  # "xml" -> only check_xxe runs; "rawbody" -> everything except check_xxe runs
        if len(param_new) == 0:
            if bodyIsXml:
                param_new = [PseudoParameter("Request Body (XML)", -1)]
                usingPseudoParam = True
                pseudoKind = "xml"
            elif len(bodyString.strip()) > 0:
                param_new = [PseudoParameter("Request Body (Raw)", -2)]
                usingPseudoParam = True
                pseudoKind = "rawbody"

        # Per vulnerability-class accumulators, keyed by VULN_DEFS key.
        status = {}
        flag = {}
        resultByKey = {}
        reqrespByKey = {}
        descByKey = {}
        markerByKey = {}
        for vd in VULN_DEFS:
            key = vd["key"]
            status[key] = self.NOT_FOUND
            flag[key] = 0
            resultByKey[key] = []
            reqrespByKey[key] = []
            descByKey[key] = []
            markerByKey[key] = []

        xxeAlreadyRun = False

        for i in range(len(param_new)):
            name = param_new[i].getName()
            ptype = param_new[i].getType()
            param_value = param_new[i].getValue()

            ctx = {
                "name": name,
                "ptype": ptype,
                "param_value": param_value,
                "request": request,
                "comp_req": Comp_req,
                "requeststring": requeststring,
                "headers": headers,
                "time_taken": time_taken,
                "body_str": bodyString,
                "body_is_xml": bodyIsXml,
                "is_pseudo": usingPseudoParam,
                "pseudo_kind": pseudoKind
            }

            for vd in VULN_DEFS:
                key = vd["key"]

                if not self.checkboxes[key].isSelected():
                    status[key] = "Disabled"
                    resultByKey[key].append("Disabled")
                    reqrespByKey[key].append(None)
                    descByKey[key].append("")
                    markerByKey[key].append(None)
                    continue

                # A bare-XML pseudo-parameter only makes sense for the XXE
                # check (there is no named value to tamper with for the
                # others). A generic raw-body pseudo-parameter is the
                # opposite: every check except XXE can still run against it
                # (by substituting/appending the payload into the raw body),
                # but XXE itself needs an actual XML body to wrap in a
                # DOCTYPE, so it is skipped here.
                if usingPseudoParam and pseudoKind == "xml" and key != "xxe":
                    resultByKey[key].append(self.NOT_FOUND)
                    reqrespByKey[key].append(None)
                    descByKey[key].append("")
                    markerByKey[key].append(None)
                    continue
                if usingPseudoParam and pseudoKind == "rawbody" and key == "xxe":
                    resultByKey[key].append(self.NOT_FOUND)
                    reqrespByKey[key].append(None)
                    descByKey[key].append("")
                    markerByKey[key].append(None)
                    continue

                # The XXE check is body-level, not parameter-level, so only
                # run it once per request no matter how many parameters
                # exist; every other parameter index just repeats "Not
                # Found" silently so the arrays stay aligned with
                # param_new.
                if key == "xxe" and xxeAlreadyRun:
                    resultByKey[key].append(self.NOT_FOUND)
                    reqrespByKey[key].append(None)
                    descByKey[key].append("")
                    markerByKey[key].append(None)
                    continue

                checkMethod = getattr(self, "check_" + key)
                result = checkMethod(ctx)

                if key == "xxe":
                    xxeAlreadyRun = True

                resultByKey[key].append(result["status"])
                reqrespByKey[key].append(result["reqresp"])
                descByKey[key].append(result["description"])
                markerByKey[key].append(result["marker"])
                flag[key] = self.checkBetterScore(result["score"], flag[key])

            if self.blindxss.isSelected() and not usingPseudoParam:
                blindxss_value = self.BlindXSSText.getText()
                self.buildAndSendUpdated(request, headers, requeststring, name, ptype, param_value, blindxss_value, blindxss_value, Comp_req)

        # Resolve the overall per-request status for each vulnerability
        # class from the best score seen across all of its parameters.
        for vd in VULN_DEFS:
            key = vd["key"]
            if status[key] == "Disabled":
                continue
            foundT, checkT = self.thresholds(key)
            if flag[key] > foundT:
                status[key] = self.FOUND
            elif flag[key] > checkT:
                status[key] = self.CHECK
            else:
                status[key] = self.NOT_FOUND

        self.addToLog(messageInfo, status, param_new, resultByKey, reqrespByKey, descByKey, markerByKey, req_time.strftime('%H:%M:%S %m/%d/%y'))

    #
    # Found/Check thresholds per vulnerability class. Kept in one place so
    # the scoring in each check_<key>() method and the final per-request
    # roll-up agree with each other.
    #
    def thresholds(self, key):
        table = {
            "xss": (3, 2),
            "sqli": (2, 1),
            "ssti": (1, 0),
            "crlf": (2, 1),
            "ssrf": (2, 1),
            "openredirect": (2, 1),
            "xxe": (2, 1),
            "oscmd": (2, 1),
            "lfi": (2, 1)
        }
        return table.get(key, (2, 1))

    #
    # Function used to check if the score originally and mentioned is better
    #
    def checkBetterScore(self, score, ogscore):
        if score > ogscore:
            ogscore = score
        return ogscore

    def makeRequest(self, messageInfo, message):
        requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
        return self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(requestURL.getHost()), int(requestURL.getPort()), requestURL.getProtocol() == "https"), message)

    #
    # Shared helper used by (almost) every check_<key>() method: swap a
    # single GET/POST/multipart/JSON parameter's value for a payload and
    # build the resulting HTTP request - this works identically no matter
    # which HTTP method (GET, POST, PUT, PATCH, DELETE, ...) the original
    # request used, since Burp's buildParameter/updateParameter operate on
    # where the parameter lives, not on the verb. A final branch handles the
    # generic raw-body pseudo-parameter (ptype -2) for requests with no
    # parseable parameters at all.
    #
    def buildUpdatedRequest(self, request, headers, requeststring, name, ptype, param_value, url_payload, json_payload):
        if ptype == 0 or ptype == 1 or ptype == 5:
            new_parameter = self._helpers.buildParameter(name, url_payload, ptype)
            return self._helpers.updateParameter(request, new_parameter)
        elif ptype == 6:
            jsonreq = re.search(r"\s([{\[].*?[}\]])$", requeststring).group(1)
            new = jsonreq.split(name + "\":", 1)[1]
            if new.startswith('"'):
                newjsonreq = jsonreq.replace(name + "\":\"" + param_value, name + "\":\"" + json_payload)
            else:
                newjsonreq = jsonreq.replace(name + "\":" + param_value, name + "\":\"" + json_payload + "\"")
            return self._helpers.buildHttpMessage(headers, newjsonreq)
        elif ptype == -2:
            # Generic raw-body fallback: the request's body is not parsed
            # URL/body/multipart/JSON parameters (e.g. a PUT/PATCH with a
            # plain-text, custom or otherwise unrecognised body), so there is
            # no named value to swap out. Substitute the payload into the
            # body text directly when it happens to contain the parameter's
            # own value, otherwise append the payload to the end of the body
            # - a standard fuzzing fallback that still exercises the same
            # response-based detections every other check relies on.
            reqInfo = self._helpers.analyzeRequest(request)
            bodyOffset = reqInfo.getBodyOffset()
            body = requeststring[bodyOffset:]
            if param_value and param_value in body:
                new_body = body.replace(param_value, json_payload, 1)
            else:
                new_body = body.rstrip("\r\n") + json_payload
            return self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(new_body))
        else:
            # Unsupported pseudo-type (e.g. the bare-XML marker, ptype -1)
            # should never reach here - XXE is handled entirely inside
            # check_xxe - but fail safe by returning the original request
            # unmodified rather than raising.
            return request

    def buildAndSendUpdated(self, request, headers, requeststring, name, ptype, param_value, url_payload, json_payload, comp_req):
        updated_request = self.buildUpdatedRequest(request, headers, requeststring, name, ptype, param_value, url_payload, json_payload)
        return self.makeRequest(comp_req, updated_request)

    # -----------------------------------------------------------------
    # check_xss - reflected-tag detection, unchanged idea from the
    # original Trishul: throw a handful of unencoded-sensitive characters
    # at the parameter and see which ones come back unescaped.
    # -----------------------------------------------------------------
    def check_xss(self, ctx):
        payload_array = ["<", ">", "\\'asd", "\\\"asd", "\\", "'\""]
        json_payload_array = ["<", ">", "\\'asd", "\\\"asd", "\\", "'\\\""]
        rand_str = "testtest"
        payload_all = "".join([rand_str + p for p in payload_array])
        json_payload = "".join([rand_str + p for p in json_payload_array])
        url_value = URLEncoder.encode(payload_all, "UTF-8")
        json_value = URLEncoder.encode(json_payload, "UTF-8")

        attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], url_value, json_value, ctx["comp_req"])
        response_str = self._helpers.bytesToString(attack.getResponse())

        score = 0
        non_encoded_symbols = ""
        for check_payload in payload_array:
            if (rand_str + check_payload) in response_str:
                non_encoded_symbols += "<br>" + check_payload.replace('<', '&lt;')
                score += 1

        status = self.NOT_FOUND
        if score > 2:
            status = self.CHECK
        if score > 3:
            status = self.FOUND

        description = ""
        if non_encoded_symbols != "":
            description = "The Payload <b>" + payload_all.replace('<', '&lt;') + "</b> was passed in the request for the parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>. Some tags were observed in the output unfiltered. A payload can be generated with the observed tags.<br>Symbols not encoded for parameter <b>" + ctx["name"] + "</b>: " + non_encoded_symbols

        return {"status": status, "score": score, "reqresp": attack, "description": description, "marker": rand_str}

    # -----------------------------------------------------------------
    # check_sqli - time-based + error-based detection, unchanged idea
    # from the original Trishul.
    # -----------------------------------------------------------------
    def check_sqli(self, ctx):
        url_value = "%27and%28select%2afrom%28select%28sleep%285%29%29%29a%29--"
        json_value = "' and (select*from(select(sleep(5)))a)--"

        orig_time = datetime.datetime.today()
        attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], url_value, json_value, ctx["comp_req"])
        new_time = datetime.datetime.today()
        diff = (new_time - orig_time).total_seconds()
        response_str = self._helpers.bytesToString(attack.getResponse())

        score = 0
        if (diff - ctx["time_taken"]) > 3:
            score = 3

        error_array = ["check the manual that corresponds to your", "You have an error", "syntax error", "SQL syntax", "SQL statement", "ERROR:", "Error:", "MySQL", "Warning:", "mysql_fetch_array()"]
        found_text = ""
        for error in error_array:
            if error in response_str:
                found_text = found_text + error
                score = score + 1

        status = self.NOT_FOUND
        foundT, checkT = self.thresholds("sqli")
        if score > checkT:
            status = self.CHECK
        if score > foundT:
            status = self.FOUND

        description = ""
        if found_text != '':
            description = "The payload <b>" + self._helpers.urlDecode(url_value) + "</b> was passed in the request for parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>. Error text was observed in the response, which indicates an Error-based SQL injection. Please check the request and response for this parameter."
        elif (diff - ctx["time_taken"]) > 3:
            description = "The payload <b>" + self._helpers.urlDecode(url_value) + "</b> was passed in the request for parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>. The response was delayed by <b>" + str(diff) + "</b> seconds compared to the original <b>" + str(ctx["time_taken"]) + "</b> seconds. This indicates a Time-based SQL injection. Please check the request and response for this parameter."

        marker = found_text if found_text != '' else None
        return {"status": status, "score": score, "reqresp": attack, "description": description, "marker": marker}

    # -----------------------------------------------------------------
    # check_ssti - unchanged idea from the original Trishul: evaluate a
    # small arithmetic expression in several template syntaxes and look
    # for the matching numeric result in the response.
    # -----------------------------------------------------------------
    def check_ssti(self, ctx):
        payload_array = ["${123*456}", "<%=123*567%>", "{{123*678}}"]
        json_payload_array = ["$\\{123*456\\}", "<%=123*567%>", "\\{\\{123*678\\}\\}"]
        rand_str = "jjjjjjj"
        payload_all = "".join([rand_str + p for p in payload_array])
        json_payload = "".join([rand_str + p for p in json_payload_array])
        url_value = URLEncoder.encode(payload_all, "UTF-8")
        json_value = URLEncoder.encode(json_payload, "UTF-8")

        attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], url_value, json_value, ctx["comp_req"])
        response_str = self._helpers.bytesToString(attack.getResponse())

        expected_output = ["56088", "69741", "83394", "3885", "777777777777777"]
        score = 0
        description = ""
        reqresp = attack
        marker = None

        if (rand_str + expected_output[0]) in response_str:
            description = "Parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b> is using a <b>Java</b> template.<br>The value <b>" + payload_all + "</b> was passed, which gave the result <b>56088</b>."
            score = 2
            marker = expected_output[0]
        elif (rand_str + expected_output[1]) in response_str:
            description = "Parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b> is using a <b>Ruby</b> template.<br>The value <b>" + payload_all + "</b> was passed, which gave the result <b>69741</b>."
            score = 2
            marker = expected_output[1]
        elif (rand_str + expected_output[2]) in response_str:
            payload_new = "{{5*'777'}}"
            json_payload_ssti = "\\{\\{5*'777'\\}\\}"
            payload = URLEncoder.encode(payload_new, "UTF-8")
            json_ssti = URLEncoder.encode(json_payload_ssti, "UTF-8")
            ssti_attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], payload, json_ssti, ctx["comp_req"])
            ssti_response_str = self._helpers.bytesToString(ssti_attack.getResponse())
            if expected_output[3] in ssti_response_str:
                description = "Parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b> is using a <b>Twig</b> template.<br>The value <b>" + payload_new + "</b> was passed, which gave the result <b>3885</b>."
                score = 2
                reqresp = ssti_attack
                marker = expected_output[3]
            elif expected_output[4] in ssti_response_str:
                description = "Parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b> is using a <b>Jinja2</b> template.<br>The value <b>" + payload_new + "</b> was passed, which gave the result <b>777777777777777</b>."
                score = 2
                reqresp = ssti_attack
                marker = expected_output[4]

        foundT, checkT = self.thresholds("ssti")
        status = self.NOT_FOUND
        if score > checkT:
            status = self.CHECK
        if score > foundT:
            status = self.FOUND

        return {"status": status, "score": score, "reqresp": reqresp, "description": description, "marker": marker}

    # -----------------------------------------------------------------
    # check_crlf - inject a CRLF sequence followed by a marker header
    # and see whether it comes back as a genuine extra response header
    # (Found) or merely unencoded in the body (Check Manually).
    # -----------------------------------------------------------------
    def check_crlf(self, ctx):
        rand_str = "trishulcrlf"
        header_name = "X-Trishul-CRLF"
        url_value = rand_str + "%0d%0a" + header_name + ":%20injected"
        json_value = rand_str + "\\r\\n" + header_name + ": injected"

        attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], url_value, json_value, ctx["comp_req"])
        response = attack.getResponse()
        response_str = self._helpers.bytesToString(response)

        score = 0
        header_found = False
        try:
            resp_headers = self._helpers.analyzeResponse(response).getHeaders()
            for h in resp_headers:
                if header_name.lower() in h.lower():
                    header_found = True
                    break
        except:
            pass

        description = ""
        marker = None
        if header_found:
            score = 4
            marker = header_name
            description = "The payload <b>" + self._helpers.urlDecode(url_value) + "</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>, and the injected <b>" + header_name + "</b> header was reflected back as a genuine, separate response header. This confirms CRLF injection / HTTP header injection."
        elif (rand_str + "\r\n" + header_name) in response_str or (rand_str + "%0d%0a" + header_name) in response_str:
            score = 2
            marker = rand_str
            description = "The payload <b>" + self._helpers.urlDecode(url_value) + "</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b> and the raw CR/LF sequence was reflected unencoded in the response. This may indicate CRLF injection; check manually whether it lands in a header context."

        foundT, checkT = self.thresholds("crlf")
        status = self.NOT_FOUND
        if score > checkT:
            status = self.CHECK
        if score > foundT:
            status = self.FOUND

        return {"status": status, "score": score, "reqresp": attack, "description": description, "marker": marker}

    # -----------------------------------------------------------------
    # check_ssrf - try the parameter against a small set of well-known
    # internal/metadata destinations (cloud metadata, localhost, and a
    # couple of common filter-bypass encodings of 127.0.0.1) and look for
    # metadata fingerprints, connection-error fingerprints, or a large
    # timing delta that suggests the server made an outbound request.
    # -----------------------------------------------------------------
    def check_ssrf(self, ctx):
        payload_array = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://localhost:80/",
            "http://127.0.0.1:80/",
            "http://0177.0.0.1/",       # octal-encoded 127.0.0.1
            "http://2130706433/",       # decimal-encoded 127.0.0.1
            "http://[::1]/"
        ]

        metadata_signatures = ["ami-id", "instance-id", "security-credentials", "AccessKeyId", "meta-data", "iam/security-credentials", "computeMetadata", "project-id"]
        error_signatures = ["Connection refused", "Failed to connect", "Could not resolve host", "getaddrinfo failed", "Name or service not known", "cURL error", "Operation timed out", "No route to host"]

        score = 0
        description = ""
        marker = None
        reqresp = None

        for metadata_url in payload_array:
            url_value = URLEncoder.encode(metadata_url, "UTF-8")
            json_value = metadata_url

            orig_time = datetime.datetime.today()
            attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], url_value, json_value, ctx["comp_req"])
            new_time = datetime.datetime.today()
            diff = (new_time - orig_time).total_seconds()
            response_str = self._helpers.bytesToString(attack.getResponse())
            if reqresp is None:
                reqresp = attack

            found_meta = [s for s in metadata_signatures if s in response_str]
            found_err = [s for s in error_signatures if s in response_str]

            if found_meta:
                score = 4
                marker = found_meta[0]
                reqresp = attack
                description = "The payload <b>" + metadata_url + "</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>, and cloud metadata content (<b>" + found_meta[0] + "</b>) was observed in the response. This confirms SSRF with access to the instance metadata service."
                break
            elif found_err and score < 2:
                score = 2
                marker = found_err[0]
                reqresp = attack
                description = "The payload <b>" + metadata_url + "</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>, and an outbound-connection error (<b>" + found_err[0] + "</b>) was observed in the response. This suggests the server attempted to reach the supplied URL; check manually for SSRF."
            elif (diff - ctx["time_taken"]) > 5 and score < 2:
                score = 2
                reqresp = attack
                description = "The payload <b>" + metadata_url + "</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>. The response was delayed by <b>" + str(diff) + "</b> seconds compared to the original <b>" + str(ctx["time_taken"]) + "</b> seconds, suggesting the server made an outbound network request before timing out. Check manually for blind SSRF."

        foundT, checkT = self.thresholds("ssrf")
        status = self.NOT_FOUND
        if score > checkT:
            status = self.CHECK
        if score > foundT:
            status = self.FOUND

        return {"status": status, "score": score, "reqresp": reqresp, "description": description, "marker": marker}

    # -----------------------------------------------------------------
    # check_openredirect - point the parameter at an external canary
    # host using a handful of common scheme/encoding bypass variants and
    # check whether the application issues a genuine 3xx redirect whose
    # Location header points at it, or reflects it in a client-side
    # redirect (meta-refresh / JS) in the response body.
    # -----------------------------------------------------------------
    def check_openredirect(self, ctx):
        canary_host = "trishul-redirect-test.burpcollaborator-canary.net"
        payload_array = [
            "https://" + canary_host + "/",
            "http://" + canary_host + "/",
            "//" + canary_host + "/",
            "https:/" + canary_host + "/",
            "/\\" + canary_host + "/",
            "https://" + canary_host + "%2f%2e%2e",
        ]

        score = 0
        description = ""
        marker = None
        reqresp = None

        for payload in payload_array:
            url_value = URLEncoder.encode(payload, "UTF-8")
            json_value = payload

            attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], url_value, json_value, ctx["comp_req"])
            response = attack.getResponse()
            response_str = self._helpers.bytesToString(response)
            if reqresp is None:
                reqresp = attack

            statusCode = None
            location = None
            try:
                respInfo = self._helpers.analyzeResponse(response)
                statusCode = respInfo.getStatusCode()
                for h in respInfo.getHeaders():
                    if h.lower().startswith("location:"):
                        location = h.split(":", 1)[1].strip()
                        break
            except:
                pass

            if location and canary_host.lower() in location.lower() and statusCode is not None and 300 <= statusCode < 400:
                score = 4
                marker = location
                reqresp = attack
                description = "The payload <b>" + payload + "</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>, and the application issued a <b>" + str(statusCode) + "</b> redirect with a <b>Location</b> header pointing at the attacker-controlled host (<b>" + location + "</b>). This confirms an open redirect."
                break
            elif canary_host.lower() in response_str.lower() and score < 2:
                score = 2
                marker = canary_host
                reqresp = attack
                description = "The payload <b>" + payload + "</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b> and the attacker-controlled host was observed reflected in the response body (for example inside a meta-refresh tag or a JavaScript redirect). Check manually for a client-side open redirect."

        foundT, checkT = self.thresholds("openredirect")
        status = self.NOT_FOUND
        if score > checkT:
            status = self.CHECK
        if score > foundT:
            status = self.FOUND

        return {"status": status, "score": score, "reqresp": reqresp, "description": description, "marker": marker}

    # -----------------------------------------------------------------
    # check_xxe - only runs when the request body is XML. Wraps the body
    # in a DOCTYPE declaring an external entity pointing at /etc/passwd,
    # substitutes the entity reference in for the parameter's own value,
    # and looks for /etc/passwd content or an XML-parser error in the
    # response.
    # -----------------------------------------------------------------
    def check_xxe(self, ctx):
        if not ctx["body_is_xml"]:
            return {"status": self.NOT_FOUND, "score": 0, "reqresp": None, "description": "", "marker": None}

        doctype = "<?xml version=\"1.0\"?><!DOCTYPE trishul [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
        body = ctx["body_str"]
        param_value = ctx["param_value"]

        # Prefer substituting the actual parameter's value (when Trishul is
        # looping over a real GET/POST/JSON-style param that happens to also
        # live inside an XML body); otherwise fall back to the first XML
        # text node we can find, which is the common case for a bare XML
        # body with no conventional parameters at all (see PseudoParameter).
        target_text = None
        if param_value and param_value in body:
            target_text = param_value
        else:
            m = re.search(r">([^<>&\s][^<>&]{0,200}?)<", body)
            if m:
                target_text = m.group(1)

        if target_text:
            new_body = doctype + body.replace(target_text, "&xxe;", 1)
        else:
            # No obvious injection point found; still test whether the
            # parser accepts our DOCTYPE/entity declaration at all.
            new_body = doctype + body

        try:
            updated_request = self._helpers.buildHttpMessage(ctx["headers"], self._helpers.stringToBytes(new_body))
            attack = self.makeRequest(ctx["comp_req"], updated_request)
            response_str = self._helpers.bytesToString(attack.getResponse())
        except:
            return {"status": self.NOT_FOUND, "score": 0, "reqresp": None, "description": "", "marker": None}

        score = 0
        description = ""
        marker = None

        if "root:" in response_str and ":0:0:" in response_str:
            score = 4
            marker = "root:"
            description = "An external entity referencing <b>file:///etc/passwd</b> was injected into the XML request body. The contents of <b>/etc/passwd</b> appear to have been returned in the response, confirming XXE."
        else:
            xml_errors = ["DOCTYPE is not allowed", "External Entity", "XMLSyntaxError", "SimpleXMLElement", "failed to load external entity", "DTD is prohibited", "ParserConfigurationException"]
            for err in xml_errors:
                if err in response_str:
                    score = 2
                    marker = err
                    description = "An external entity referencing <b>file:///etc/passwd</b> was injected into the XML request body. An XML-parser error (<b>" + err + "</b>) was observed, which indicates the DOCTYPE/entity was processed to some degree. Check manually for XXE."
                    break

        foundT, checkT = self.thresholds("xxe")
        status = self.NOT_FOUND
        if score > checkT:
            status = self.CHECK
        if score > foundT:
            status = self.FOUND

        if ctx["is_pseudo"]:
            description += "<br><br><i>Note: this finding relates to the overall XML request body, not a single named parameter, since no conventional parameters were found in this request.</i>"

        return {"status": status, "score": score, "reqresp": attack, "description": description, "marker": marker}

    # -----------------------------------------------------------------
    # check_oscmd - a time-based "sleep" probe (mirrors the SQLi check)
    # followed by an output-based probe looking for the unmistakable
    # "uid=...(...) gid=...(...)" signature of an executed `id` command.
    # -----------------------------------------------------------------
    def check_oscmd(self, ctx):
        time_url_value = URLEncoder.encode(";sleep 5;", "UTF-8")
        time_json_value = "; sleep 5;"

        orig_time = datetime.datetime.today()
        time_attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], time_url_value, time_json_value, ctx["comp_req"])
        new_time = datetime.datetime.today()
        diff = (new_time - orig_time).total_seconds()

        score = 0
        if (diff - ctx["time_taken"]) > 3:
            score = 3

        out_url_value = URLEncoder.encode("|id", "UTF-8")
        out_json_value = "| id"
        out_attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], out_url_value, out_json_value, ctx["comp_req"])
        out_response_str = self._helpers.bytesToString(out_attack.getResponse())

        output_match = re.search(r"uid=\d+\([a-zA-Z0-9_\-]+\)\s+gid=\d+", out_response_str)

        description = ""
        marker = None
        reqresp = time_attack

        if output_match:
            score = 4
            reqresp = out_attack
            marker = output_match.group(0)
            description = "The payload <b>|id</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b> and the output of the <b>id</b> command (<b>" + output_match.group(0) + "</b>) was observed in the response. This confirms OS command injection."
        elif (diff - ctx["time_taken"]) > 3:
            description = "The payload <b>;sleep 5;</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>. The response was delayed by <b>" + str(diff) + "</b> seconds compared to the original <b>" + str(ctx["time_taken"]) + "</b> seconds. This indicates a time-based OS command injection. Please check the request and response for this parameter."

        foundT, checkT = self.thresholds("oscmd")
        status = self.NOT_FOUND
        if score > checkT:
            status = self.CHECK
        if score > foundT:
            status = self.FOUND

        return {"status": status, "score": score, "reqresp": reqresp, "description": description, "marker": marker}

    # -----------------------------------------------------------------
    # check_lfi - try a handful of traversal/encoding variants aimed at
    # /etc/passwd and win.ini, and look for well-known file content
    # signatures, or (more weakly) the raw payload being reflected
    # verbatim as a sign that no sanitisation is happening at all.
    # -----------------------------------------------------------------
    def check_lfi(self, ctx):
        payload_array = [
            "../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "/etc/passwd%00",
            "../../../../../../windows/win.ini"
        ]
        file_signatures = [
            (re.compile(r"root:.*?:0:0:"), "/etc/passwd"),
            (re.compile(r"daemon:.*?:1:1:"), "/etc/passwd"),
            (re.compile(r"\[extensions\]", re.IGNORECASE), "win.ini"),
            (re.compile(r"for 16-bit app support", re.IGNORECASE), "win.ini")
        ]

        score = 0
        description = ""
        marker = None
        reqresp = None
        matched_payload = None

        for payload in payload_array:
            attack = self.buildAndSendUpdated(ctx["request"], ctx["headers"], ctx["requeststring"], ctx["name"], ctx["ptype"], ctx["param_value"], payload, payload, ctx["comp_req"])
            response_str = self._helpers.bytesToString(attack.getResponse())
            if reqresp is None:
                reqresp = attack

            matched = False
            for pattern, label in file_signatures:
                m = pattern.search(response_str)
                if m:
                    score = 4
                    marker = m.group(0)
                    matched_payload = payload
                    reqresp = attack
                    description = "The payload <b>" + payload + "</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b>, and content matching <b>" + label + "</b> (<b>" + m.group(0) + "</b>) was observed in the response. This confirms local file disclosure via path traversal."
                    matched = True
                    break
            if matched:
                break
            if payload in response_str and score < 2:
                score = 2
                matched_payload = payload
                marker = payload
                description = "The payload <b>" + payload + "</b> was passed in parameter <b>" + self._helpers.urlDecode(ctx["name"]) + "</b> and was reflected unencoded in the response. No known file-content signature was matched though; check manually for local file inclusion."

        foundT, checkT = self.thresholds("lfi")
        status = self.NOT_FOUND
        if score > checkT:
            status = self.CHECK
        if score > foundT:
            status = self.FOUND

        return {"status": status, "score": score, "reqresp": reqresp, "description": description, "marker": marker}

    def addToLog(self, messageInfo, status, parameters, resultByKey, reqrespByKey, descByKey, markerByKey, req_time):
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        method = requestInfo.getMethod()
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(self._callbacks.saveBuffersToTempFiles(messageInfo), requestInfo.getUrl(), method, status, req_time, parameters, resultByKey, reqrespByKey, descByKey, markerByKey))
        SwingUtilities.invokeLater(UpdateTableEDT(self, "insert", row, row))
        self._lock.release()


#
# Autoscroll enabling feature
#
class autoScrollListener(AdjustmentListener):
    def __init__(self, extender):
        self._extender = extender

    def adjustmentValueChanged(self, e):
        if self._extender.autoScroll.isSelected() is True:
            e.getAdjustable().setValue(e.getAdjustable().getMaximum())


#
# Menu Item added on Right Click which sends request to Trishul
#
class handleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):
        start_new_thread(self._extender.sendRequestToTrishul, (self._messageInfo,))


#
# Function to insert request details into the table
#
class UpdateTableEDT(Runnable):
    def __init__(self, extender, action, firstRow, lastRow):
        self._extender = extender
        self._action = action
        self._firstRow = firstRow
        self._lastRow = lastRow

    def run(self):
        if self._action == "insert":
            self._extender.fireTableRowsInserted(self._firstRow, self._lastRow)
        elif self._action == "update":
            self._extender.fireTableRowsUpdated(self._firstRow, self._lastRow)
        elif self._action == "delete":
            self._extender.fireTableRowsDeleted(self._firstRow, self._lastRow)
        else:
            print("Invalid action in UpdateTableEDT")


#
# extend JTable to handle cell selection
#
class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self.addMouseListener(mouseclick(self._extender))
        self.getColumnModel().getColumn(0).setPreferredWidth(0)
        self.setRowSelectionAllowed(True)
        return

    # Set color for cells in tables
    def prepareRenderer(self, renderer, row, col):
        comp = JTable.prepareRenderer(self, renderer, row, col)
        value = self._extender.getValueAt(self._extender.logTable.convertRowIndexToModel(row), col)

        firstVulnCol = 4
        lastVulnCol = 4 + len(VULN_DEFS) - 1

        if firstVulnCol <= col <= lastVulnCol:
            if value == self._extender.FOUND:
                comp.setBackground(Color(179, 0, 0))
                comp.setForeground(Color.WHITE)
            elif value == self._extender.CHECK:
                comp.setBackground(Color(255, 153, 51))
                comp.setForeground(Color.BLACK)
            elif value == self._extender.NOT_FOUND:
                comp.setBackground(Color.LIGHT_GRAY)
                comp.setForeground(Color.BLACK)
            elif value == "Disabled":
                comp.setBackground(Color.LIGHT_GRAY)
                comp.setForeground(Color.BLACK)
        else:
            comp.setForeground(Color.BLACK)
            comp.setBackground(Color.LIGHT_GRAY)

        selectedRow = self._extender.logTable.getSelectedRow()
        if selectedRow == row:
            comp.setBackground(Color.WHITE)
            comp.setForeground(Color.BLACK)
        return comp

    # open Issue tab to display vulnerable parameters
    def changeSelection(self, row, col, toggle, extend):

        if col >= 0:
            self.performAction(row)
            self._extender.issuetab.setSelectedIndex(1)
            self._extender.tree.expandRow(0)

        firstVulnCol = 4
        lastVulnCol = 4 + len(VULN_DEFS) - 1
        if firstVulnCol <= col <= lastVulnCol:
            vulnIndex = col - firstVulnCol
            for idx in range(len(VULN_DEFS)):
                if idx == vulnIndex:
                    self._extender.tree.expandRow(idx + 1)
                else:
                    self._extender.tree.collapseRow(idx + 1)

        JTable.changeSelection(self, row, col, toggle, extend)
        return

    # Add parameters to array for every issue found for a particular request
    def performAction(self, row):
        model = self._extender.tree.getModel()
        root = model.getRoot()
        root.removeAllChildren()
        model.reload()

        self.vulnRoots = {}
        for vd in VULN_DEFS:
            node = DefaultMutableTreeNode(vd["tree"])
            root.add(node)
            self.vulnRoots[vd["key"]] = node

        logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
        parameter = logEntry._parameter

        for i in range(len(parameter)):
            for vd in VULN_DEFS:
                key = vd["key"]
                results = logEntry._resultByKey[key]
                if i < len(results) and (results[i] == self._extender.CHECK or results[i] == self._extender.FOUND):
                    self._extender.addIssues(self.vulnRoots[key], [parameter[i].getName()])

        self._extender.rowSelected = row

        return


#
# Log to Store Data of Requests
#
class LogEntry:

    def __init__(self, requestResponse, url, method, status, req_time, parameter, resultByKey, reqrespByKey, descByKey, markerByKey):
        self._requestResponse = requestResponse
        self._url = url
        self._method = method
        self._status = status
        self._req_time = req_time
        self._parameter = parameter
        self._resultByKey = resultByKey
        self._reqrespByKey = reqrespByKey
        self._descByKey = descByKey
        self._markerByKey = markerByKey
        return


#
# Mouse Adapter to click on Table and Tree to display data
#
class mouseclick(MouseAdapter):

    def __init__(self, extender):
        self._extender = extender

    def mouseReleased(self, evt):
        if evt.button == 3:
            self._extender.menu.show(evt.getComponent(), evt.getX(), evt.getY())
        self.path = self._extender.tree.getLastSelectedPathComponent()
        if self.path != None:
            row = self._extender.rowSelected
            logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
            parameter = logEntry._parameter
            url = logEntry._url.toString()

            vulnByTree = {}
            for vd in VULN_DEFS:
                vulnByTree[vd["tree"]] = vd

            parentLabel = str(self.path.getParent())
            if parentLabel in vulnByTree:
                vd = vulnByTree[parentLabel]
                key = vd["key"]
                results = logEntry._resultByKey[key]
                reqresps = logEntry._reqrespByKey[key]
                descs = logEntry._descByKey[key]
                markers = logEntry._markerByKey[key]

                for i in range(len(parameter)):
                    if str(self.path) == parameter[i].getName():
                        if i >= len(reqresps) or reqresps[i] is None:
                            continue
                        self.showAdvisory(vd, logEntry, url, parameter[i], results[i], reqresps[i], descs[i], markers[i])
                        break

    def showAdvisory(self, vd, logEntry, url, parameter, result, reqresp, description, marker):
        self._extender.textfield.setText("")
        confidence = self.checkConfidence(result)
        kit = self._extender.kit
        doc = self._extender.doc

        kit.insertHTML(doc, doc.getLength(), "<h1>" + vd["label"] + "</h1>", 0, 0, None)
        kit.insertHTML(doc, doc.getLength(), "<br><table cellspacing=\"1\" cellpadding=\"0\"><tr><td>Issue:</td> <td><b>" + vd["label"] + "</b></td></tr><tr><td>Severity:</td> <td><b>" + vd["severity"] + "</b></td></tr><tr><td>Confidence:</td> <td>" + confidence + "</td></tr><tr><td>URL:</td> <td><b>" + url + "</b></td></tr></table>", 0, 0, None)
        kit.insertHTML(doc, doc.getLength(), "<br style=\"margin:0px\"><h3>Description</h3>", 0, 0, None)
        kit.insertHTML(doc, doc.getLength(), "The Parameter <b>" + self._extender._helpers.urlDecode(parameter.getName()) + "</b> is Vulnerable to <b>" + vd["label"] + "</b>", 0, 0, None)
        kit.insertHTML(doc, doc.getLength(), description, 0, 0, None)
        kit.insertHTML(doc, doc.getLength(), vd["general"], 0, 0, None)
        kit.insertHTML(doc, doc.getLength(), "<br><h3>Remediation</h3>", 0, 0, None)
        kit.insertHTML(doc, doc.getLength(), vd["remediation"], 0, 0, None)
        self._extender.textfield.setCaretPosition(0)

        self._extender.selectedreq = reqresp
        self._extender._requestViewer.setMessage(reqresp.getRequest(), True)
        self._extender._responseViewer.setMessage(reqresp.getResponse(), False)
        self._extender._currentlyDisplayedItem = reqresp
        self._extender._texteditor.setText(reqresp.getResponse())
        if marker:
            self._extender._texteditor.setSearchExpression(marker)
        self._extender.markHttpMessage(reqresp, marker if marker else None)

    # Color of Confidence in Description
    def checkConfidence(self, value):
        if value == self._extender.FOUND:
            return "<b style=\"color:red;\">Firm</b>"
        elif value == self._extender.CHECK:
            return "<b style=\"color:orange;\">Tentative</b>"
        return ""
