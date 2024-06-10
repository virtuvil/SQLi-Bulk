from burp import IBurpExtender, IHttpListener, IContextMenuFactory, ITab
from java.awt import BorderLayout
from javax.swing import JPanel, JLabel, JTextField, JButton, JOptionPane
import os

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Save Requests to TXT")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)

        self.output_dir = "burp_requests"
        self.input_dir = "burp_input"
        self.scope = None

        # Create the custom tab
        self.main_panel = JPanel(BorderLayout())
        self.create_tab()

        # Add the custom tab to Burp Suite
        self._callbacks.addSuiteTab(self)

    def create_tab(self):
        # Create components for the tab
        label_output_dir = JLabel("Output Directory:")
        self.text_output_dir = JTextField(self.output_dir, 20)
        label_input_dir = JLabel("Input Directory:")
        self.text_input_dir = JTextField(self.input_dir, 20)
        label_scope = JLabel("Scope (host, leave empty for all):")
        self.text_scope = JTextField(20)
        save_button = JButton("Save Configuration", actionPerformed=self.save_config)

        # Add components to the panel
        panel = JPanel()
        panel.add(label_output_dir)
        panel.add(self.text_output_dir)
        panel.add(label_input_dir)
        panel.add(self.text_input_dir)
        panel.add(label_scope)
        panel.add(self.text_scope)
        panel.add(save_button)

        # Add the panel to the main panel
        self.main_panel.add(panel, BorderLayout.NORTH)

    def save_config(self, event):
        self.output_dir = self.text_output_dir.getText()
        self.input_dir = self.text_input_dir.getText()
        scope_input = self.text_scope.getText().strip()
        if scope_input:
            self.scope = self._helpers.buildHttpService(scope_input, 80)
        else:
            self.scope = None
        JOptionPane.showMessageDialog(None, "Configuration updated successfully.")

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
        self.text_output_dir.setText(self.output_dir)
        self.text_input_dir.setText(self.input_dir)
        scope_text = self.scope.getHost() if self.scope else ""
        self.text_scope.setText(scope_text)
        JOptionPane.showMessageDialog(None, "Configuration panel opened. Please use the custom tab to update settings.")

    # ITab interface methods
    def getTabCaption(self):
        return "TXT Generator"

    def getUiComponent(self):
        return self.main_panel

