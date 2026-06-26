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

    self.metadataLabel = [NSTextField labelWithString:@"No executable loaded"];
    self.metadataLabel.font = [NSFont systemFontOfSize:12 weight:NSFontWeightMedium];
    self.metadataLabel.textColor = NSColor.secondaryLabelColor;
    self.metadataLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
    [root addArrangedSubview:self.metadataLabel];

    NSSplitView *split = [[NSSplitView alloc] initWithFrame:NSZeroRect];
    split.vertical = YES;
    split.dividerStyle = NSSplitViewDividerStyleThin;
    split.translatesAutoresizingMaskIntoConstraints = NO;
    [root addArrangedSubview:split];
    [split.heightAnchor constraintGreaterThanOrEqualToConstant:520].active = YES;

    NSView *leftPane = [self paneWithTitle:@"Disassembly" textView:&_disassemblyTextView];
    NSView *rightPane = [self paneWithTitle:@"Decompiled Code" textView:&_pseudocodeTextView];
    [split addSubview:leftPane];
    [split addSubview:rightPane];
    [leftPane.widthAnchor constraintGreaterThanOrEqualToConstant:420].active = YES;
    [rightPane.widthAnchor constraintGreaterThanOrEqualToConstant:420].active = YES;
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
    [scrollView.heightAnchor constraintGreaterThanOrEqualToConstant:480].active = YES;

    *textViewOut = textView;
    return pane;
}

- (void)showWelcomeText {
    self.disassemblyTextView.string = @"Open an executable to view Capstone disassembly here.\n";
    self.pseudocodeTextView.string = @"Open an executable to generate C-like pseudocode here.\n\nSupported containers: Mach-O, Universal Mach-O, ELF, PE/COFF, and raw binary fallback.\n";
}

- (void)decompileCurrentFile {
    self.statusLabel.stringValue = @"Decompiling...";
    self.metadataLabel.stringValue = self.currentFileURL.path;

    DCPseudocodeStyle style = (DCPseudocodeStyle)self.stylePopup.indexOfSelectedItem;
    NSError *error = nil;
    DCDecompilerResult *result = [self.engine decompileFileAtURL:self.currentFileURL style:style error:&error];
    if (!result) {
        self.statusLabel.stringValue = @"Failed";
        self.disassemblyTextView.string = @"";
        self.pseudocodeTextView.string = error.localizedDescription ?: @"Unknown decompiler error.";
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
    self.disassemblyTextView.string = result.disassembly;
    self.pseudocodeTextView.string = result.pseudocode;
}

@end
