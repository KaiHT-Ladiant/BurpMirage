package com.burpmirage.burp.ui;

import com.burpmirage.burp.intercept.InterceptController;
import com.burpmirage.burp.model.ExtensionSettings;
import com.burpmirage.burp.model.InterceptedPacket;
import com.burpmirage.burp.util.HexUtils;
import com.burpmirage.burp.util.I18n;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JToggleButton;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.KeyboardFocusManager;
import java.awt.KeyEventDispatcher;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

/**
 * Live intercept view — Forward: Ctrl+Shift+F, Drop: Ctrl+D.
 */
public final class InterceptorPanel extends JPanel {
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final InterceptController controller;
    private final ExtensionSettings settings;
    private final HexEditorPanel hexEditor = new HexEditorPanel();
    private final JLabel header = new JLabel(I18n.get("intercept.waiting"));
    private final JToggleButton interceptToggle = new JToggleButton();
    private final JLabel queueLabel = new JLabel(I18n.format("intercept.queue", 0));
    private final Consumer<InterceptedPacket> sendToRepeater;

    private InterceptedPacket current;
    private KeyEventDispatcher shortcutDispatcher;

    public InterceptorPanel(
            InterceptController controller,
            ExtensionSettings settings,
            Consumer<InterceptedPacket> sendToRepeater
    ) {
        super(new BorderLayout(8, 8));
        this.controller = controller;
        this.settings = settings;
        this.sendToRepeater = sendToRepeater != null ? sendToRepeater : p -> {};
        setBorder(new EmptyBorder(8, 8, 8, 8));
        setFocusable(true);

        interceptToggle.setSelected(settings.interceptEnabled());
        interceptToggle.setFocusPainted(false);
        interceptToggle.setFont(interceptToggle.getFont().deriveFont(Font.BOLD));
        applyInterceptButtonStyle();
        interceptToggle.addActionListener(e -> {
            settings.setInterceptEnabled(interceptToggle.isSelected());
            applyInterceptButtonStyle();
        });

        JPanel north = new JPanel(new BorderLayout());
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT));
        left.add(interceptToggle);
        left.add(queueLabel);
        north.add(left, BorderLayout.WEST);
        north.add(header, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton forward = new JButton(I18n.get("intercept.forward"));
        JButton drop = new JButton(I18n.get("intercept.drop"));
        JButton toRepeater = new JButton(I18n.get("intercept.to_repeater"));
        JButton applyPattern = new JButton(I18n.get("intercept.apply_pattern"));
        forward.addActionListener(e -> doForward());
        drop.addActionListener(e -> doDrop());
        toRepeater.addActionListener(e -> doSendToRepeater());
        applyPattern.addActionListener(e -> {
            if (current == null) return;
            byte[] next = controller.applySearchReplace(current.originalData(), hexEditor.getData());
            hexEditor.setData(next);
            hexEditor.setMeta(I18n.format("intercept.original_ascii",
                    HexUtils.toAsciiPreview(current.originalData(), 120))
                    + "  |  logical len=" + HexUtils.logicalWireLength(current.originalData(), next));
        });
        buttons.add(applyPattern);
        buttons.add(toRepeater);
        buttons.add(drop);
        buttons.add(forward);
        north.add(buttons, BorderLayout.EAST);

        add(north, BorderLayout.NORTH);
        add(hexEditor, BorderLayout.CENTER);

        JPanel south = new JPanel(new FlowLayout(FlowLayout.LEFT));
        south.add(new JLabel(I18n.get("intercept.shortcuts")));
        add(south, BorderLayout.SOUTH);

        installContextMenu();
        installGlobalShortcuts();
        controller.setUiPresenter(this::present);
    }

    private void installContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem sendItem = new JMenuItem(I18n.get("intercept.to_repeater"));
        sendItem.addActionListener(e -> doSendToRepeater());
        JMenuItem forwardItem = new JMenuItem(I18n.get("intercept.menu.forward"));
        forwardItem.setAccelerator(KeyStroke.getKeyStroke(
                KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        forwardItem.addActionListener(e -> doForward());
        JMenuItem dropItem = new JMenuItem(I18n.get("intercept.menu.drop"));
        dropItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_D, InputEvent.CTRL_DOWN_MASK));
        dropItem.addActionListener(e -> doDrop());
        menu.add(sendItem);
        menu.addSeparator();
        menu.add(forwardItem);
        menu.add(dropItem);

        MouseAdapter popup = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybeShow(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybeShow(e);
            }

            private void maybeShow(MouseEvent e) {
                if (e.isPopupTrigger() && current != null) {
                    menu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        };
        hexEditor.addMouseListener(popup);
        hexEditor.dumpArea().addMouseListener(popup);
        hexEditor.asciiArea().addMouseListener(popup);
        addMouseListener(popup);
    }

    private void installGlobalShortcuts() {
        shortcutDispatcher = e -> {
            if (e.getID() != KeyEvent.KEY_PRESSED) {
                return false;
            }
            if (!isShowing()) {
                return false;
            }
            // Only when focus is inside this interceptor panel (not whole Burp window)
            var focus = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
            if (focus == null || !SwingUtilities.isDescendingFrom(focus, this)) {
                return false;
            }
            boolean ctrl = (e.getModifiersEx() & InputEvent.CTRL_DOWN_MASK) != 0;
            boolean shift = (e.getModifiersEx() & InputEvent.SHIFT_DOWN_MASK) != 0;
            if (!ctrl) {
                return false;
            }
            int code = e.getKeyCode();
            // Forward: Ctrl+Shift+F only (Ctrl+F is taken by Burp)
            if (code == KeyEvent.VK_F && shift) {
                SwingUtilities.invokeLater(this::doForward);
                e.consume();
                return true;
            }
            if (code == KeyEvent.VK_D && !shift) {
                SwingUtilities.invokeLater(this::doDrop);
                e.consume();
                return true;
            }
            if (code == KeyEvent.VK_R && shift) {
                SwingUtilities.invokeLater(this::doSendToRepeater);
                e.consume();
                return true;
            }
            return false;
        };
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(shortcutDispatcher);
    }

    private void present(InterceptedPacket packet) {
        SwingUtilities.invokeLater(() -> {
            current = packet;
            header.setText(String.format(
                    "%s  %s  pid=%d  api=%s  peer=%s  len=%d  @ %s",
                    packet.direction().label(),
                    packet.processName(),
                    packet.pid(),
                    packet.apiName(),
                    packet.peer(),
                    packet.length(),
                    TS.format(packet.timestamp())
            ));
            hexEditor.setMeta(I18n.format("intercept.original_ascii", HexUtils.toAsciiPreview(packet.originalData(), 120)));
            hexEditor.setData(packet.data());
            queueLabel.setText(I18n.format("intercept.queue", controller.queue().size()));
            requestFocusInWindow();
        });
    }

    private void doForward() {
        if (current == null) {
            return;
        }
        byte[] edited = hexEditor.getData();
        byte[] prepared = HexUtils.applyLogicalLength(current.originalData(), edited);
        // Reflect length fields in HEX before delivery; send logical wire length to Frida.
        hexEditor.setData(prepared);
        byte[] wire = HexUtils.forWireDelivery(current.originalData(), prepared);
        controller.forwardCurrent(wire);
        clearView();
    }

    private void doDrop() {
        if (current == null) {
            return;
        }
        controller.dropCurrent();
        clearView();
    }

    private void doSendToRepeater() {
        if (current == null) {
            return;
        }
        // Send current editor bytes (may include unsaved edits)
        InterceptedPacket copy = InterceptedPacket.create(
                current.pid(),
                current.processName(),
                current.direction(),
                current.apiName(),
                current.peer(),
                current.socketFd(),
                hexEditor.getData()
        );
        sendToRepeater.accept(copy);
    }

    private void clearView() {
        current = null;
        hexEditor.clear();
        header.setText(I18n.get("intercept.waiting"));
        queueLabel.setText(I18n.format("intercept.queue", controller.queue().size()));
    }

    /**
     * Burp Proxy–style intercept control: a toggle button whose label/color flip with state.
     * ON ≈ amber (classic Intercept is on), OFF ≈ default button look.
     */
    private void applyInterceptButtonStyle() {
        boolean on = interceptToggle.isSelected();
        interceptToggle.setText(on ? I18n.get("intercept.on") : I18n.get("intercept.off"));
        if (on) {
            interceptToggle.setBackground(new Color(0xF5, 0xA6, 0x23));
            interceptToggle.setForeground(Color.BLACK);
            interceptToggle.setOpaque(true);
            interceptToggle.setContentAreaFilled(true);
        } else {
            Color bg = UIManager.getColor("Button.background");
            Color fg = UIManager.getColor("Button.foreground");
            interceptToggle.setBackground(bg != null ? bg : null);
            interceptToggle.setForeground(fg != null ? fg : null);
            interceptToggle.setOpaque(false);
            interceptToggle.setContentAreaFilled(true);
        }
    }
}
