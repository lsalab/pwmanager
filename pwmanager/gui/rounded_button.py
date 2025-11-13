"""
Custom rounded button widget using Canvas for full control over appearance.

Provides a button with rounded corners that works reliably across all contexts.
"""

import tkinter as tk

from pwmanager.gui.styles import StylingColors


class RoundedButton(tk.Canvas):
    """
    A custom button widget with rounded corners using Canvas.
    
    This provides full control over the button appearance and works reliably
    in both main windows and dialogs.
    """
    
    def __init__(self, parent, text='', command=None, width=None, height=None,
                 corner_radius=12, bg_color=None, hover_color=None, 
                 text_color='white', font=None, state='normal', canvas_bg=None, **kwargs):
        """
        Create a rounded button.
        
        Args:
            parent: Parent widget
            text: Button text
            command: Command to execute on click
            width: Button width (None for auto)
            height: Button height (default: 35)
            corner_radius: Radius of rounded corners (default: 12)
            bg_color: Background color (default: accent color)
            hover_color: Hover state color (default: hover color)
            text_color: Text color (default: white)
            font: Font tuple (default: Segoe UI, 9, bold)
            state: Button state ('normal' or 'disabled')
            canvas_bg: Canvas background color to match window theme (default: BG color)
            **kwargs: Additional Canvas options
        """
        # Set defaults
        if bg_color is None:
            bg_color = StylingColors.ACCENT.value
        if hover_color is None:
            hover_color = StylingColors.HOVER.value
        if font is None:
            font = ('Segoe UI', 9, 'bold')
        if height is None:
            height = 35
        if canvas_bg is None:
            canvas_bg = StylingColors.BG.value
        
        # Calculate minimum width based on text
        if width is None:
            temp_canvas = tk.Canvas(parent)
            text_width = temp_canvas.create_text(0, 0, text=text, font=font)
            bbox = temp_canvas.bbox(text_width)
            text_w = bbox[2] - bbox[0] if bbox else 50
            temp_canvas.destroy()
            width = max(text_w + 24, 80)  # Add padding, minimum 80px
        
        # Initialize Canvas with background matching window theme
        super().__init__(parent, width=width, height=height, 
                        highlightthickness=0, relief='flat', bd=0, 
                        bg=canvas_bg, **kwargs)
        
        # Store attributes
        self._text = text
        self._command = command
        self._corner_radius = corner_radius
        self._bg_color = bg_color
        self._hover_color = hover_color
        self._text_color = text_color
        self._font = font
        self._state = state
        self._is_hovered = False
        self._is_pressed = False
        
        # Bind events
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_press)
        self.bind('<ButtonRelease-1>', self._on_release)
        self.bind('<Motion>', self._on_motion)
        self.bind('<Configure>', self._on_configure)
        
        # Draw initial button (after a short delay to ensure widget is sized)
        self.after_idle(self._draw)
    
    def _draw(self):
        """Draw the button with current state."""
        self.delete('all')
        
        # Determine current color
        if self._state == 'disabled':
            color = StylingColors.DISABLED.value
            text_color = '#ffffff'
        elif self._is_pressed or self._is_hovered:
            color = self._hover_color
            text_color = self._text_color
        else:
            color = self._bg_color
            text_color = self._text_color
        
        # Get dimensions
        width = self.winfo_width()
        height = self.winfo_height()
        
        if width <= 1 or height <= 1:
            # Widget not yet sized, skip drawing
            return
        
        # Draw rounded rectangle using arcs and rectangles
        radius = min(self._corner_radius, width // 2, height // 2)
        
        # Draw the main rectangle (excluding corners)
        self.create_rectangle(radius, 0, width - radius, height, 
                            fill=color, outline=color, width=0)
        self.create_rectangle(0, radius, width, height - radius, 
                            fill=color, outline=color, width=0)
        
        # Draw the four rounded corners using arcs
        # Top-left
        self.create_arc(0, 0, radius * 2, radius * 2, 
                       start=90, extent=90, fill=color, outline=color, width=0)
        # Top-right
        self.create_arc(width - radius * 2, 0, width, radius * 2, 
                       start=0, extent=90, fill=color, outline=color, width=0)
        # Bottom-right
        self.create_arc(width - radius * 2, height - radius * 2, width, height, 
                       start=270, extent=90, fill=color, outline=color, width=0)
        # Bottom-left
        self.create_arc(0, height - radius * 2, radius * 2, height, 
                       start=180, extent=90, fill=color, outline=color, width=0)
        
        # Draw text
        self.create_text(width // 2, height // 2, text=self._text, 
                        fill=text_color, font=self._font)
    
    def _on_enter(self, event):
        """Handle mouse enter event."""
        if self._state == 'normal':
            self._is_hovered = True
            self._draw()
            self.config(cursor='hand2')
    
    def _on_leave(self, event):
        """Handle mouse leave event."""
        self._is_hovered = False
        self._is_pressed = False
        self._draw()
        self.config(cursor='')
    
    def _on_press(self, event):
        """Handle mouse press event."""
        if self._state == 'normal':
            self._is_pressed = True
            self._draw()
    
    def _on_release(self, event):
        """Handle mouse release event."""
        if self._state == 'normal' and self._is_pressed:
            self._is_pressed = False
            self._draw()
            # Execute command if within button bounds
            x, y = event.x, event.y
            if 0 <= x <= self.winfo_width() and 0 <= y <= self.winfo_height():
                if self._command:
                    self._command()
    
    def _on_motion(self, event):
        """Handle mouse motion event."""
        # Update hover state based on position
        x, y = event.x, event.y
        width = self.winfo_width()
        height = self.winfo_height()
        was_hovered = self._is_hovered
        self._is_hovered = (0 <= x <= width and 0 <= y <= height and self._state == 'normal')
        
        if was_hovered != self._is_hovered:
            self._draw()
            self.config(cursor='hand2' if self._is_hovered else '')
    
    def _on_configure(self, event):
        """Handle widget resize."""
        self._draw()
    
    def config(self, **kwargs):
        """Override config to handle state changes."""
        if 'state' in kwargs:
            state_val = kwargs.pop('state')
            # Handle both string and tkinter constants
            if state_val == 'normal' or state_val == tk.NORMAL:
                self._state = 'normal'
            elif state_val == 'disabled' or state_val == tk.DISABLED:
                self._state = 'disabled'
            else:
                self._state = str(state_val)
            self._draw()
        if 'text' in kwargs:
            self._text = kwargs.pop('text')
            self._draw()
        if 'command' in kwargs:
            self._command = kwargs.pop('command')
        super().config(**kwargs)
    
    def configure(self, **kwargs):
        """Alias for config."""
        self.config(**kwargs)
    
    def cget(self, key):
        """Get configuration value."""
        if key == 'state':
            return self._state
        if key == 'text':
            return self._text
        if key == 'command':
            return self._command
        return super().cget(key)

