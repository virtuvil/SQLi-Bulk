from burp import IBurpExtender, IHttpListener, IContextMenuFactory, IContextMenuInvocation
from burp import IHttpRequestResponse, IScannerCheck, IScanIssue
from java.awt.event import ActionListener
from javax.swing import JMenuItem, JOptionPane
import os

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Save Requests to TXT")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)
        self.output_dir = "burp_requests"
        self.scope = None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            if self.scope and not self._callbacks.isInScope(messageInfo.getHttpService()):
                return
            request_info = self._helpers.analyzeRequest(messageInfo)
            request = messageInfo.getRequest()
            request_str = self._helpers.bytesToString(request)
            host = request_info.getUrl().getHost()
            self.save_request_to_file(host, request_str)

    def save_request_to_file(self, host, request_str):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        index = len(os.listdir(self.output_dir))
        file_path = os.path.join(self.output_dir, "request_{0}_{1}.txt".format(index, host))
        with open(file_path, 'w') as f:
            f.write(request_str)

    def createMenuItems(self, invocation):
        menu_list = []
        menu_item = JMenuItem("Configure Save Requests Extension", actionPerformed=self.show_config_dialog)
        menu_list.append(menu_item)
        return menu_list

    def show_config_dialog(self, event):
        output_dir = JOptionPane.showInputDialog("Enter output directory:")
        if output_dir:
            self.output_dir = output_dir

        scope_input = JOptionPane.showInputDialog("Enter scope (leave empty for all):")
        if scope_input:
            self.scope = self._helpers.buildHttpService(scope_input, 80)
        else:
            self.scope = None
        JOptionPane.showMessageDialog(None, "Configuration updated successfully.")

