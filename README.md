# Enhanced-Base64-Gzip-Editor

```python
# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IHttpListener, IContextMenuInvocation
from javax.swing import JMenuItem, JOptionPane, JTextArea, JScrollPane, JButton, JPanel, JDialog
from java.util import ArrayList
from java.awt import BorderLayout, Font
import base64
import gzip
from io import BytesIO
from java.io import ByteArrayOutputStream


class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Enhanced Base64 & Gzip Editor")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        if self.context.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            menu_list.add(JMenuItem("Edit Request (Base64 & Gzip)", actionPerformed=self.edit_request))
        if self.context.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
            menu_list.add(JMenuItem("Edit Response (Base64 & Gzip)", actionPerformed=self.edit_response))
        return menu_list

    def edit_request(self, event):
        self.edit_data(self.context.getSelectedMessages()[0].getRequest(), True)

    def edit_response(self, event):
        self.edit_data(self.context.getSelectedMessages()[0].getResponse(), False)

    def edit_data(self, data, is_request):
        try:
            selection_bounds = self.context.getSelectionBounds()
            if not selection_bounds:
                JOptionPane.showMessageDialog(None, "Please select Base64 data.", "Error", JOptionPane.ERROR_MESSAGE)
                return

            start, end = selection_bounds
            selected_text = self._helpers.bytesToString(data[start:end])

            try:
                decoded_data = base64.b64decode(selected_text.encode('utf-8'))
            except Exception as e:
                JOptionPane.showMessageDialog(None, "Error decoding Base64: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
                return

            try:
                with gzip.GzipFile(fileobj=BytesIO(decoded_data)) as gz:
                    readable_text = gz.read()
                readable_text = self.decode_with_fallback(readable_text)
            except Exception as e:
                JOptionPane.showMessageDialog(None, "Error extracting Gzip: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
                return

            title = "Edit Request" if is_request else "View Response"
            self.show_edit_window(readable_text, data, start, end, is_request, title)

        except Exception as e:
            JOptionPane.showMessageDialog(None, "Unexpected error: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def decode_with_fallback(self, binary_data):
        """Try decoding with multiple encodings."""
        for encoding in ["utf-8", "windows-1251", "latin-1"]:
            try:
                return binary_data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return binary_data.decode("utf-8", errors="replace")

    def show_edit_window(self, readable_text, data, start, end, is_request, title):
        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setSize(600, 400)
        dialog.setResizable(True)

        edit_area = JTextArea(readable_text)
        edit_area.setFont(Font("Arial", Font.PLAIN, 12))
        edit_area.setLineWrap(True)
        edit_area.setWrapStyleWord(True)
        scroll_pane = JScrollPane(edit_area)

        # Show Save, Cancel, and OK buttons only for Request
        if is_request:
            save_button = JButton("Save", actionPerformed=lambda e: self.save_changes(edit_area, data, start, end, is_request, dialog))
            cancel_button = JButton("Cancel", actionPerformed=lambda e: dialog.dispose())
            ok_button = JButton("OK", actionPerformed=lambda e: self.close_if_unchanged(edit_area, readable_text, dialog))

            button_panel = JPanel()
            button_panel.add(save_button)
            button_panel.add(ok_button)
            button_panel.add(cancel_button)
        else:
            # Only show Close button for Response
            close_button = JButton("Close", actionPerformed=lambda e: dialog.dispose())
            button_panel = JPanel()
            button_panel.add(close_button)

        main_panel = JPanel(BorderLayout())
        main_panel.add(scroll_pane, BorderLayout.CENTER)
        main_panel.add(button_panel, BorderLayout.SOUTH)

        dialog.add(main_panel)
        dialog.setLocationRelativeTo(None)
        dialog.setModal(False)  # Allow opening multiple dialogs
        dialog.setVisible(True)

    def save_changes(self, edit_area, data, start, end, is_request, dialog):
        modified_text = edit_area.getText()

        try:
            compressed_data = self.compress_gzip(modified_text)
            encoded_data = base64.b64encode(compressed_data).decode('utf-8')

            baos = ByteArrayOutputStream()
            baos.write(data[:start])
            baos.write(encoded_data.encode('utf-8'))
            baos.write(data[end:])

            if is_request:
                self.context.getSelectedMessages()[0].setRequest(baos.toByteArray())
            else:
                self.context.getSelectedMessages()[0].setResponse(baos.toByteArray())

            JOptionPane.showMessageDialog(None, "Data updated successfully!", "Success", JOptionPane.INFORMATION_MESSAGE)
            dialog.dispose()

        except Exception as e:
            JOptionPane.showMessageDialog(None, "Error updating data: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def close_if_unchanged(self, edit_area, original_text, dialog):
        current_text = edit_area.getText()
        if current_text != original_text:
            JOptionPane.showMessageDialog(None, "Unsaved changes exist. Please save or cancel.", "Warning", JOptionPane.WARNING_MESSAGE)
        else:
            dialog.dispose()

    def compress_gzip(self, data):
        with BytesIO() as byte_io:
            with gzip.GzipFile(fileobj=byte_io, mode='wb') as gz:
                gz.write(data.encode('utf-8'))
            return byte_io.getvalue()
```

---

## Description

1. Some text will be there :
- The first one
- The second one

## Features 

1. The first feature
2. The second one

![Snow leopard](https://encrypted-tbn3.gstatic.com/images?q=tbn:ANd9GcQR6JobTpe8G1uwx7844qANeNFqJ4yi18vkXhLhzrXYYqeKR5QEfMYLB_9aBfBj1ElqjEPjZTC83SegBzNccgpz1w)

![Snow leopard screenhot](img/chrome_z4WZhOWScT.png)
