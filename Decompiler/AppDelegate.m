#import "AppDelegate.h"
#import "DecompilerEngine.h"

@interface AppDelegate ()

@property (strong) IBOutlet NSWindow *window;
@property (nonatomic, strong) DCDecompilerEngine *engine;
@property (nonatomic, strong) NSTextView *disassemblyTextView;
@property (nonatomic, strong) NSTextView *pseudocodeTextView;
@property (nonatomic, strong) NSTextField *metadataLabel;
@property (nonatomic, strong) NSTextField *statusLabel;
@property (nonatomic, strong) NSPopUpButton *stylePopup;
@property (nonatomic, strong) NSURL *currentFileURL;

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    self.engine = [DCDecompilerEngine new];
    [self configureWindow];
    [self buildInterface];
    [self showWelcomeText];
}

- (BOOL)applicationSupportsSecureRestorableState:(NSApplication *)app {
    return YES;
}

- (IBAction)openDocument:(id)sender {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    panel.canChooseFiles = YES;
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = NO;
    panel.title = @"Open Executable";
    panel.prompt = @"Decompile";
    panel.message = @"Choose a Mach-O, ELF, PE/COFF, or raw executable image.";

    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse result) {
        if (result == NSModalResponseOK) {
            self.currentFileURL = panel.URL;
            [self decompileCurrentFile];
        }
    }];
}

- (void)styleDidChange:(id)sender {
    if (self.currentFileURL) {
        [self decompileCurrentFile];
    }
}

- (void)configureWindow {
    self.window.title = @"Decompiler";
    self.window.minSize = NSMakeSize(980, 620);
    [self.window setFrame:NSMakeRect(120, 120, 1220, 760) display:YES];
}

- (void)buildInterface {
    NSView *content = self.window.contentView;
    content.wantsLayer = YES;
    content.layer.backgroundColor = NSColor.windowBackgroundColor.CGColor;

    NSStackView *root = [[NSStackView alloc] initWithFrame:NSZeroRect];
    root.orientation = NSUserInterfaceLayoutOrientationVertical;
    root.spacing = 10;
    root.edgeInsets = NSEdgeInsetsMake(12, 12, 12, 12);
    root.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:root];

    [NSLayoutConstraint activateConstraints:@[
        [root.topAnchor constraintEqualToAnchor:content.topAnchor],
        [root.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
        [root.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
        [root.bottomAnchor constraintEqualToAnchor:content.bottomAnchor],
    ]];

    NSStackView *toolbar = [[NSStackView alloc] initWithFrame:NSZeroRect];
    toolbar.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    toolbar.alignment = NSLayoutAttributeCenterY;
    toolbar.spacing = 10;

    NSButton *openButton = [NSButton buttonWithTitle:@"Open Executable" target:self action:@selector(openDocument:)];
    openButton.bezelStyle = NSBezelStyleRounded;
    [toolbar addArrangedSubview:openButton];

    NSTextField *styleLabel = [NSTextField labelWithString:@"Pseudocode"];
    [toolbar addArrangedSubview:styleLabel];

    self.stylePopup = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    [self.stylePopup addItemsWithTitles:DCDecompilerEngine.pseudocodeStyleNames];
    self.stylePopup.target = self;
    self.stylePopup.action = @selector(styleDidChange:);
    [self.stylePopup.widthAnchor constraintGreaterThanOrEqualToConstant:160].active = YES;
    [toolbar addArrangedSubview:self.stylePopup];

    self.statusLabel = [NSTextField labelWithString:@"Ready"];
    self.statusLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
    [toolbar addArrangedSubview:self.statusLabel];
    [self.statusLabel setContentHuggingPriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];

    [root addArrangedSubview:toolbar];
    [toolbar setContentHuggingPriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationVertical];

    self.metadataLabel = [NSTextField labelWithString:@"No executable loaded"];
    self.metadataLabel.font = [NSFont systemFontOfSize:12 weight:NSFontWeightMedium];
    self.metadataLabel.textColor = NSColor.secondaryLabelColor;
    self.metadataLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
    [root addArrangedSubview:self.metadataLabel];
    [self.metadataLabel setContentHuggingPriority:NSLayoutPriorityRequired forOrientation:NSLayoutConstraintOrientationVertical];

    NSSplitView *split = [[NSSplitView alloc] initWithFrame:NSZeroRect];
    split.vertical = YES;
    split.dividerStyle = NSSplitViewDividerStyleThin;
    split.translatesAutoresizingMaskIntoConstraints = NO;
    split.autoresizesSubviews = YES;
    [root addArrangedSubview:split];
    [split setContentHuggingPriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationVertical];
    [split setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationVertical];

    NSView *leftPane = [self paneWithTitle:@"Disassembly" textView:&_disassemblyTextView];
    NSView *rightPane = [self paneWithTitle:@"Decompiled Code" textView:&_pseudocodeTextView];
    [split addSubview:leftPane];
    [split addSubview:rightPane];
    [leftPane.widthAnchor constraintGreaterThanOrEqualToConstant:420].active = YES;
    [rightPane.widthAnchor constraintGreaterThanOrEqualToConstant:420].active = YES;
    [split setHoldingPriority:NSLayoutPriorityDefaultLow forSubviewAtIndex:0];
    [split setHoldingPriority:NSLayoutPriorityDefaultLow forSubviewAtIndex:1];
    [self configureDisassemblyTextView];
    [self configurePseudocodeTextView];
}

- (NSView *)paneWithTitle:(NSString *)title textView:(NSTextView * __strong *)textViewOut {
    NSView *pane = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 500, 500)];
    pane.translatesAutoresizingMaskIntoConstraints = NO;

    NSStackView *stack = [[NSStackView alloc] initWithFrame:NSZeroRect];
    stack.orientation = NSUserInterfaceLayoutOrientationVertical;
    stack.spacing = 6;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [pane addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:pane.topAnchor],
        [stack.leadingAnchor constraintEqualToAnchor:pane.leadingAnchor],
        [stack.trailingAnchor constraintEqualToAnchor:pane.trailingAnchor],
        [stack.bottomAnchor constraintEqualToAnchor:pane.bottomAnchor],
    ]];

    NSTextField *label = [NSTextField labelWithString:title];
    label.font = [NSFont systemFontOfSize:13 weight:NSFontWeightSemibold];
    [stack addArrangedSubview:label];

    NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:NSZeroRect];
    scrollView.hasVerticalScroller = YES;
    scrollView.hasHorizontalScroller = YES;
    scrollView.borderType = NSBezelBorder;
    scrollView.autohidesScrollers = NO;
    [scrollView setContentHuggingPriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationVertical];
    [scrollView setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationVertical];

    NSTextView *textView = [[NSTextView alloc] initWithFrame:NSZeroRect];
    textView.editable = NO;
    textView.selectable = YES;
    textView.richText = NO;
    textView.automaticQuoteSubstitutionEnabled = NO;
    textView.automaticDashSubstitutionEnabled = NO;
    textView.font = [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular];
    textView.textContainerInset = NSMakeSize(8, 8);
    textView.minSize = NSMakeSize(0, 0);
    textView.maxSize = NSMakeSize(CGFLOAT_MAX, CGFLOAT_MAX);
    textView.horizontallyResizable = YES;
    textView.verticallyResizable = YES;
    textView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    textView.textContainer.containerSize = NSMakeSize(CGFLOAT_MAX, CGFLOAT_MAX);
    textView.textContainer.widthTracksTextView = NO;
    scrollView.documentView = textView;

    [stack addArrangedSubview:scrollView];

    *textViewOut = textView;
    return pane;
}

- (void)showWelcomeText {
    [self setDisassemblyText:@"Open an executable to view Capstone disassembly here.\n"];
    [self setPseudocodeText:@"Open an executable to generate C-like pseudocode here.\n\nSupported containers: Mach-O, Universal Mach-O, ELF, PE/COFF, and raw binary fallback.\n"];
}

- (void)decompileCurrentFile {
    self.statusLabel.stringValue = @"Decompiling...";
    self.metadataLabel.stringValue = self.currentFileURL.path;

    DCPseudocodeStyle style = (DCPseudocodeStyle)self.stylePopup.indexOfSelectedItem;
    NSError *error = nil;
    DCDecompilerResult *result = [self.engine decompileFileAtURL:self.currentFileURL style:style error:&error];
    if (!result) {
        self.statusLabel.stringValue = @"Failed";
        [self setDisassemblyText:@""];
        [self setPseudocodeText:error.localizedDescription ?: @"Unknown decompiler error."];
        return;
    }

    NSMutableString *meta = [NSMutableString stringWithFormat:@"%@ | %@ | entry %@ | %@",
                             result.formatName,
                             result.architectureName,
                             result.entryPointDescription,
                             self.currentFileURL.lastPathComponent];
    if (result.warnings.count > 0) {
        [meta appendFormat:@" | %@", [result.warnings componentsJoinedByString:@" "]];
    }

    self.statusLabel.stringValue = @"Complete";
    self.metadataLabel.stringValue = meta;
    [self setDisassemblyText:result.disassembly];
    [self setPseudocodeText:result.pseudocode];
}

- (void)configureDisassemblyTextView {
    NSColor *background = NSColor.blackColor;
    self.disassemblyTextView.backgroundColor = background;
    self.disassemblyTextView.textColor = NSColor.whiteColor;
    self.disassemblyTextView.insertionPointColor = NSColor.whiteColor;
    self.disassemblyTextView.drawsBackground = YES;
    self.disassemblyTextView.enclosingScrollView.drawsBackground = YES;
    self.disassemblyTextView.enclosingScrollView.backgroundColor = background;
}

- (void)configurePseudocodeTextView {
    NSColor *background = [NSColor colorWithCalibratedRed:0.92 green:0.97 blue:1.0 alpha:1.0];
    self.pseudocodeTextView.backgroundColor = background;
    self.pseudocodeTextView.textColor = NSColor.blackColor;
    self.pseudocodeTextView.insertionPointColor = NSColor.blackColor;
    self.pseudocodeTextView.drawsBackground = YES;
    self.pseudocodeTextView.enclosingScrollView.drawsBackground = YES;
    self.pseudocodeTextView.enclosingScrollView.backgroundColor = background;
}

- (void)setDisassemblyText:(NSString *)text {
    NSDictionary<NSAttributedStringKey, id> *attributes = @{
        NSFontAttributeName: [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular],
        NSForegroundColorAttributeName: NSColor.whiteColor,
        NSBackgroundColorAttributeName: NSColor.blackColor,
    };
    NSAttributedString *attributed = [[NSAttributedString alloc] initWithString:text ?: @"" attributes:attributes];
    [self.disassemblyTextView.textStorage setAttributedString:attributed];
}

- (void)setPseudocodeText:(NSString *)text {
    [self.pseudocodeTextView.textStorage setAttributedString:[self highlightedPseudocode:text ?: @""]];
}

- (NSAttributedString *)highlightedPseudocode:(NSString *)text {
    NSColor *background = [NSColor colorWithCalibratedRed:0.92 green:0.97 blue:1.0 alpha:1.0];
    NSFont *font = [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular];
    NSMutableAttributedString *highlighted = [[NSMutableAttributedString alloc] initWithString:text attributes:@{
        NSFontAttributeName: font,
        NSForegroundColorAttributeName: NSColor.blackColor,
        NSBackgroundColorAttributeName: background,
    }];

    [self applyPattern:@"\\b(int|void|return|if|goto|asm|call|flags|compare)\\b"
                 color:[NSColor colorWithCalibratedRed:0.0 green:0.18 blue:0.58 alpha:1.0]
                    to:highlighted];
    [self applyPattern:@"\\b(0x[0-9a-fA-F]+|[0-9]+)\\b"
                 color:[NSColor colorWithCalibratedRed:0.45 green:0.0 blue:0.55 alpha:1.0]
                    to:highlighted];
    [self applyPattern:@"//[^\\n]*|;[^\\n]*"
                 color:[NSColor colorWithCalibratedRed:0.28 green:0.36 blue:0.42 alpha:1.0]
                    to:highlighted];
    [self applyPattern:@"\"([^\"\\\\]|\\\\.)*\""
                 color:[NSColor colorWithCalibratedRed:0.60 green:0.10 blue:0.05 alpha:1.0]
                    to:highlighted];
    [self applyPattern:@"\\b(label_[A-Za-z0-9_]+|block_[A-Fa-f0-9]+|i[0-9]{4})\\b"
                 color:[NSColor colorWithCalibratedRed:0.0 green:0.42 blue:0.48 alpha:1.0]
                    to:highlighted];

    return highlighted;
}

- (void)applyPattern:(NSString *)pattern color:(NSColor *)color to:(NSMutableAttributedString *)text {
    NSError *error = nil;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:&error];
    if (!regex || error) {
        return;
    }
    NSRange fullRange = NSMakeRange(0, text.length);
    [regex enumerateMatchesInString:text.string options:0 range:fullRange usingBlock:^(NSTextCheckingResult *result, NSMatchingFlags flags, BOOL *stop) {
        if (result.range.location != NSNotFound && NSMaxRange(result.range) <= text.length) {
            [text addAttribute:NSForegroundColorAttributeName value:color range:result.range];
        }
    }];
}

@end
