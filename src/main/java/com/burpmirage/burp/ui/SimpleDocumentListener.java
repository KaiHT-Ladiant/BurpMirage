package com.burpmirage.burp.ui;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

final class SimpleDocumentListener implements DocumentListener {
    private final Runnable onChange;

    SimpleDocumentListener(Runnable onChange) {
        this.onChange = onChange;
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
        onChange.run();
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        onChange.run();
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        onChange.run();
    }
}
