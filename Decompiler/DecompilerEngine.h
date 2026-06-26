#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, DCPseudocodeStyle) {
    DCPseudocodeStyleStructuredC = 0,
    DCPseudocodeStyleCompactC = 1,
    DCPseudocodeStyleVerboseIR = 2,
    DCPseudocodeStyleControlFlow = 3,
};

@interface DCDecompilerResult : NSObject

@property (nonatomic, copy) NSString *formatName;
@property (nonatomic, copy) NSString *architectureName;
@property (nonatomic, copy) NSString *entryPointDescription;
@property (nonatomic, copy) NSString *disassembly;
@property (nonatomic, copy) NSString *pseudocode;
@property (nonatomic, copy) NSArray<NSString *> *warnings;

@end

@interface DCDecompilerEngine : NSObject

+ (NSArray<NSString *> *)pseudocodeStyleNames;
- (DCDecompilerResult *)decompileFileAtURL:(NSURL *)url
                                     style:(DCPseudocodeStyle)style
                                     error:(NSError **)error;

@end
