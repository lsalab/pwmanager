"""
Centralized styling configuration for the password manager GUI.

Provides consistent modern styling for both the main window and dialogs.
"""

import tkinter as tk
import tkinter.ttk as ttk
from enum import Enum

# Try to import PIL for rounded button images
try:
    from PIL import Image, ImageDraw, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


class StylingColors(Enum):
    """Modern color scheme for the password manager GUI."""
    BG = '#d0d0d0'
    FG = '#000000'
    ACCENT = '#404040'
    HOVER = '#b0b0b0'
    BORDER = '#c0c0c0'
    ENTRY_BG = '#ffffff'
    ENTRY_FG = '#000000'
    ERROR = '#c04040'
    DISABLED = '#808040'

# Font configuration
FONT_FAMILY = 'Segoe UI'
FONT_SIZE_NORMAL = 10
FONT_SIZE_LARGE = 11
FONT_SIZE_SMALL = 9

# Button corner radius for rounded buttons
BUTTON_CORNER_RADIUS = 8


def configure_main_window_styles(root: tk.Tk, style: ttk.Style):
    """
    Configure ttk styles for the main application window.
    
    Args:
        root: The main Tk root window
        style: The ttk.Style instance to configure
    """
    # Set theme
    style.theme_use('alt')
    
    # Configure root window background
    root.configure(bg=StylingColors.BG.value)
    
    # Configure ttk styles
    style.configure('TFrame', background=StylingColors.BG.value)
    style.configure('TLabel', 
                    background=StylingColors.BG.value, 
                    foreground=StylingColors.FG.value, 
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL))
    style.configure('TButton', 
                    background=StylingColors.ACCENT.value,
                    foreground='white',
                    borderwidth=0,
                    focuscolor='none',
                    padding=(12, 6),
                    font=(FONT_FAMILY, FONT_SIZE_SMALL, 'bold'))
    style.map('TButton',
              background=[('active', StylingColors.HOVER.value), ('pressed', StylingColors.HOVER.value)])
    style.configure('TEntry',
                    fieldbackground=StylingColors.ENTRY_BG.value,
                    foreground=StylingColors.FG.value,
                    borderwidth=1,
                    relief='solid',
                    padding=(8, 4),
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL))
    style.map('TEntry',
              bordercolor=[('focus', StylingColors.ACCENT.value)])
    style.configure('Treeview',
                    background=StylingColors.ENTRY_BG.value,
                    foreground=StylingColors.ENTRY_FG.value,
                    fieldbackground=StylingColors.ENTRY_BG.value,
                    borderwidth=1,
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL),
                    rowheight=28)
    style.configure('Treeview.Heading',
                    background=StylingColors.FG.value,
                    foreground='white',
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL, 'bold'),
                    padding=8)
    # Explicitly disable hover effects on headers - keep same style regardless of mouse state
    style.map('Treeview.Heading',
              background=[('active', StylingColors.FG.value),
                         ('pressed', StylingColors.FG.value)],
              foreground=[('active', 'white'),
                         ('pressed', 'white')])
    style.map('Treeview',
              background=[('selected', StylingColors.ACCENT.value)],
              foreground=[('selected', 'white')])
    style.configure('TScrollbar',
                    background=StylingColors.BORDER.value,
                    troughcolor=StylingColors.BG.value,
                    borderwidth=0,
                    arrowcolor=StylingColors.FG.value,
                    darkcolor=StylingColors.BORDER.value,
                    lightcolor=StylingColors.BORDER.value)


def configure_dialog_styles(dialog_window: tk.Toplevel, style: ttk.Style):
    """
    Configure ttk styles for dialog windows.
    
    Args:
        dialog_window: The Toplevel dialog window
        style: The ttk.Style instance to configure
    """
    # Configure dialog window background
    dialog_window.configure(bg=StylingColors.BG.value)
    
    # Configure dialog-specific ttk styles
    style.configure('Dialog.TFrame', background=StylingColors.BG.value)
    style.configure('Dialog.TLabel', 
                    background=StylingColors.BG.value, 
                    foreground=StylingColors.FG.value, 
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL))
    style.configure('Dialog.TButton', 
                    background=StylingColors.ACCENT.value,
                    foreground='white',
                    borderwidth=0,
                    focuscolor='none',
                    padding=(12, 6),
                    font=(FONT_FAMILY, FONT_SIZE_SMALL, 'bold'))
    style.map('Dialog.TButton',
              background=[('active', StylingColors.HOVER.value), 
                         ('pressed', StylingColors.HOVER.value), 
                         ('disabled', StylingColors.DISABLED.value)])
    style.configure('Dialog.TEntry',
                    fieldbackground=StylingColors.ENTRY_BG.value,
                    foreground=StylingColors.FG.value,
                    borderwidth=1,
                    relief='solid',
                    padding=(8, 4),
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL))
    style.map('Dialog.TEntry',
              bordercolor=[('focus', StylingColors.ACCENT.value)])


def get_entry_style_config():
    """
    Get styling configuration for tk.Entry widgets (used for password fields).
    
    Returns:
        dict: Dictionary of styling options for tk.Entry
    """
    return {
        'bg': StylingColors.ENTRY_BG.value,
        'fg': StylingColors.FG.value,
        'font': (FONT_FAMILY, FONT_SIZE_NORMAL),
        'relief': 'solid',
        'bd': 1,
        'highlightthickness': 1,
        'highlightcolor': StylingColors.ACCENT.value,
        'highlightbackground': StylingColors.BORDER.value
    }


def _hex_to_rgb(hex_color: str) -> tuple:
    """Convert hex color to RGB tuple."""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))


def _create_rounded_button_image(width: int, height: int, bg_color: str, 
                                  corner_radius: int = BUTTON_CORNER_RADIUS) -> ImageTk.PhotoImage:
    """
    Create a rounded rectangle button image.
    
    Args:
        width: Button width in pixels
        height: Button height in pixels
        bg_color: Background color (hex string)
        corner_radius: Radius of rounded corners
        
    Returns:
        PhotoImage object for use with ttk.Button
    """
    if not HAS_PIL:
        return None
    
    # Create image with the button background color (not transparent)
    # This prevents black corners from showing through
    rgb = _hex_to_rgb(bg_color)
    img = Image.new('RGB', (width, height), rgb)
    draw = ImageDraw.Draw(img)
    
    # Draw rounded rectangle with the same color (fills the entire area)
    draw.rounded_rectangle(
        [(0, 0), (width - 1, height - 1)],
        radius=corner_radius,
        fill=rgb,
        outline=rgb  # Same color for outline to avoid borders
    )
    
    return ImageTk.PhotoImage(img)


def _create_button_images(style: ttk.Style, style_name: str, 
                         normal_color: str, hover_color: str, 
                         disabled_color: str = None):
    """
    Create rounded button images for different states using PIL.
    
    This function creates rounded rectangle images and applies them to buttons
    using a border image approach that works with ttk's layout system.
    
    Args:
        style: ttk.Style instance
        style_name: Style name (e.g., 'TButton' or 'Dialog.TButton')
        normal_color: Normal state color
        hover_color: Hover/pressed state color
        disabled_color: Disabled state color (optional)
    """
    if not HAS_PIL:
        return
    
    # Skip dialog buttons - they have display issues with layout modification
    if 'Dialog' in style_name:
        return
    
    # Create images with sufficient size for border image scaling
    # The border image will be sliced into 9 parts for proper scaling
    width, height = 200, 50
    radius = BUTTON_CORNER_RADIUS
    
    # Create images for different states
    normal_img = _create_rounded_button_image(width, height, normal_color)
    hover_img = _create_rounded_button_image(width, height, hover_color)
    disabled_img = None
    if disabled_color:
        disabled_img = _create_rounded_button_image(width, height, disabled_color or StylingColors.DISABLED.value)
    
    if normal_img:
        # Store images to prevent garbage collection
        if not hasattr(style, '_button_images'):
            style._button_images = {}
        style._button_images[style_name] = {
            'normal': normal_img,
            'hover': hover_img,
            'disabled': disabled_img
        }
        
        try:
            # Get original layout
            try:
                original_layout = style.layout(style_name)
            except Exception:
                original_layout = None
            
            # Clean up any existing image element first
            try:
                style.element_delete(f'{style_name}.image')
            except Exception:
                pass
            
            # Configure button to remove background (will use image instead)
            style.configure(style_name, background='', borderwidth=0, relief='flat')
            
            # Create the image element - this will be the button background
            style.element_create(
                f'{style_name}.image',
                'image',
                normal_img,
                ('active', hover_img),
                ('pressed', hover_img),
                ('disabled', disabled_img) if disabled_img else (),
                sticky='nsew'
            )
            
            # Create a simple, reliable layout structure
            # Image as base layer, then focus/padding/label on top
            new_layout = [
                (f'{style_name}.image', {'sticky': 'nsew'}),
                ('Button.focus', {'sticky': 'nsew', 'children': [
                    ('Button.padding', {'sticky': 'nsew', 'children': [
                        ('Button.label', {'sticky': 'nsew'})
                    ]})
                ]})
            ]
            
            # Apply the layout
            style.layout(style_name, new_layout)
            
            # Ensure foreground color is set
            style.configure(style_name, foreground='white')
            
        except Exception:
            # On any error, clean up and restore normal button
            try:
                style.element_delete(f'{style_name}.image')
            except Exception:
                pass
            # Restore normal button styling
            style.configure(style_name, background=normal_color, relief='flat')


def configure_main_window_styles(root: tk.Tk, style: ttk.Style):
    """
    Configure ttk styles for the main application window.
    
    Args:
        root: The main Tk root window
        style: The ttk.Style instance to configure
    """
    # Set theme
    style.theme_use('alt')
    
    # Configure root window background
    root.configure(bg=StylingColors.BG.value)
    
    # Configure ttk styles
    style.configure('TFrame', background=StylingColors.BG.value)
    style.configure('TLabel', 
                    background=StylingColors.BG.value, 
                    foreground=StylingColors.FG.value, 
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL))
    
    # Configure button style first
    style.configure('TButton', 
                    background=StylingColors.ACCENT.value,
                    foreground='white',
                    borderwidth=0,
                    focuscolor='none',
                    padding=(12, 6),
                    font=(FONT_FAMILY, FONT_SIZE_SMALL, 'bold'))
    style.map('TButton',
              background=[('active', StylingColors.HOVER.value), ('pressed', StylingColors.HOVER.value)])
    
    # Create rounded button images (simplified approach)
    _create_button_images(style, 'TButton', StylingColors.ACCENT.value, StylingColors.HOVER.value)
    
    style.configure('TEntry',
                    fieldbackground=StylingColors.ENTRY_BG.value,
                    foreground=StylingColors.FG.value,
                    borderwidth=1,
                    relief='solid',
                    padding=(8, 4),
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL))
    style.map('TEntry',
              bordercolor=[('focus', StylingColors.ACCENT.value)])
    style.configure('Treeview',
                    background=StylingColors.ENTRY_BG.value,
                    foreground=StylingColors.ENTRY_FG.value,
                    fieldbackground=StylingColors.ENTRY_BG.value,
                    borderwidth=1,
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL),
                    rowheight=28)
    style.configure('Treeview.Heading',
                    background=StylingColors.FG.value,
                    foreground='white',
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL, 'bold'),
                    padding=8)
    # Explicitly disable hover effects on headers - keep same style regardless of mouse state
    style.map('Treeview.Heading',
              background=[('active', StylingColors.FG.value),
                         ('pressed', StylingColors.FG.value)],
              foreground=[('active', 'white'),
                         ('pressed', 'white')])
    style.map('Treeview',
              background=[('selected', StylingColors.ACCENT.value)],
              foreground=[('selected', 'white')])
    style.configure('TScrollbar',
                    background=StylingColors.BORDER.value,
                    troughcolor=StylingColors.BG.value,
                    borderwidth=0,
                    arrowcolor=StylingColors.FG.value,
                    darkcolor=StylingColors.BORDER.value,
                    lightcolor=StylingColors.BORDER.value)


def configure_dialog_styles(dialog_window: tk.Toplevel, style: ttk.Style):
    """
    Configure ttk styles for dialog windows.
    
    Args:
        dialog_window: The Toplevel dialog window
        style: The ttk.Style instance to configure
    """
    # Configure dialog window background
    dialog_window.configure(bg=StylingColors.BG.value)
    
    # Configure dialog-specific ttk styles
    style.configure('Dialog.TFrame', background=StylingColors.BG.value)
    style.configure('Dialog.TLabel', 
                    background=StylingColors.BG.value, 
                    foreground=StylingColors.FG.value, 
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL))
    
    # Configure button style first
    style.configure('Dialog.TButton', 
                    background=StylingColors.ACCENT.value,
                    foreground='white',
                    borderwidth=0,
                    focuscolor='none',
                    padding=(12, 6),
                    font=(FONT_FAMILY, FONT_SIZE_SMALL, 'bold'))
    style.map('Dialog.TButton',
              background=[('active', StylingColors.HOVER.value), 
                         ('pressed', StylingColors.HOVER.value), 
                         ('disabled', StylingColors.DISABLED.value)])
    
    # Rounded corners disabled for dialog buttons - causes display issues
    # Main window buttons can use rounded corners, but dialogs need standard buttons
    # _create_button_images(style, 'Dialog.TButton', StylingColors.ACCENT.value, StylingColors.HOVER.value, StylingColors.DISABLED.value)
    style.configure('Dialog.TEntry',
                    fieldbackground=StylingColors.ENTRY_BG.value,
                    foreground=StylingColors.FG.value,
                    borderwidth=1,
                    relief='solid',
                    padding=(8, 4),
                    font=(FONT_FAMILY, FONT_SIZE_NORMAL))
    style.map('Dialog.TEntry',
              bordercolor=[('focus', StylingColors.ACCENT.value)])

