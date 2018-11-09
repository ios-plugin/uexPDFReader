//
//  EUExPDFReader.m
//  AppCan
//
//  Created by AppCan on 13-3-21.
//
//

#import "EUExPDFReader.h"
#import "ReaderViewController.h"
#import "UexEMMGTMBase64.h"



@interface EUExPDFReader()<ReaderViewControllerDelegate,UIWebViewDelegate>
@property (nonatomic,strong)ReaderViewController *readerController;
@property (nonatomic,strong)UIWebView *pdfView;
@end

@implementation EUExPDFReader



- (void)openPDFReader:(NSMutableArray *)inArguments{
    
    ACArgsUnpack(NSString *inPath,NSString *encryptStr,ACJSFunctionRef *callback) = inArguments;
    NSInteger  isEncryptValue = [encryptStr integerValue];
    if (!inPath) {
        
        [callback executeWithArguments: ACArgsPack(@(1))];

        return;
    }
    
    //这里是为了防止前端在某些框架的影响下，多次调用同一方法导致崩溃
    if (self.readerController) {
        return;
    }
    
    NSString *absPath = [self absPath:inPath];
    NSString *kResScheme = @"res://";
    if ([inPath hasPrefix:kResScheme]) {
        NSString *documentPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES).firstObject;
        NSString *filePath = [inPath substringFromIndex:kResScheme.length];
        NSString *copyPath = [documentPath stringByAppendingPathComponent:filePath];
        if([[NSFileManager defaultManager] copyItemAtPath:absPath toPath:copyPath error:nil]){
            absPath = copyPath;
        }
    }
    
    //判断是否是加密的PDF(isEncryptValue:是否为加密  1：加密  0：非加密)
    if (isEncryptValue == 1) {
        [self func_decodeFile:absPath withNewName:absPath];
    }
    
    //Document password (for unlocking most encrypted PDF files)
    NSString *phrase = nil;
    ReaderDocument *document = [ReaderDocument withDocumentFilePath:absPath password:phrase];
    if (!document) {
        
        [callback executeWithArguments: ACArgsPack(@(1))];
        
        return;
    }
    else
    {
        [callback executeWithArguments: ACArgsPack(@(0))];
        NSLog(@"%s [ReaderDocument withDocumentFilePath:'%@' password:'%@'] failed.", __FUNCTION__, absPath, phrase);
        NSLog(@"没有PDF文件");
    }
    if (!self.readerController) {
        self.readerController = [[ReaderViewController alloc] initWithReaderDocument:document withEUExObj:self];
    }
    self.readerController.delegate = self;
    [[self.webViewEngine viewController] presentViewController:self.readerController animated:YES completion:nil];
   
 
}


/**
 *文件加密
 \array
 \filePath 需要加密的文件路径
 */
-(void)fileEncrypt:(NSMutableArray *)array{
    @try{
        if ([array isKindOfClass:[NSMutableArray class]] && [array count] > 0) {
            NSLog(@"appcan-->uexEMM-->fileEncrypt-->array is %@",array);
            NSString *srcPath = [array objectAtIndex:0];
            //            srcPath = [NSHomeDirectory() stringByAppendingFormat:@"/Documents/1.mp4"];
            if (![[NSFileManager defaultManager] fileExistsAtPath:srcPath]) {
                NSString *jsString = [NSString stringWithFormat:@"uexPDFReader.cbFileEncrypt(\"0\",\"0\",\'');"];
                if ([NSThread isMainThread]) {
                  //  [self.meBrwView stringByEvaluatingJavaScriptFromString:jsString];
                     [self.webViewEngine evaluateScript:jsString];
                    
                }else{
                    [self performSelectorOnMainThread:@selector(callBackMethod:) withObject:jsString waitUntilDone:NO];
                }
                return;
            }
            [self func_encodeFile:srcPath withNewName:srcPath];
            NSString *jsString = [NSString stringWithFormat:@"uexPDFReader.cbFileEncrypt(\"0\",\"0\",\"%@\");",srcPath];
            if ([NSThread isMainThread]) {
               // [self.meBrwView stringByEvaluatingJavaScriptFromString:jsString];
                 [self.webViewEngine evaluateScript:jsString];
                
            }else{
                [self performSelectorOnMainThread:@selector(callBackMethod:) withObject:jsString waitUntilDone:NO];
            }
        }
    }@catch (NSException * e){
        NSLog(@"appcan-->uexEMM-->fileEncrypt-->catch e is %@",e);
    }
}

#define Key_Count (17)//加密字符串长度
static char arrayForEncode[Key_Count] = "appcan@3g2win.com";

-(BOOL)func_decodeFile:(NSString *)filePath withNewName:(NSString*)newFilePath {
    if (nil == filePath || NO == [[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        NSString *jsString = [NSString stringWithFormat:@"uexPDFReader.cbFileDecrypt(\"0\",\"0\",\'');"];
        if ([NSThread isMainThread]) {
           // [self.meBrwView stringByEvaluatingJavaScriptFromString:jsString];
            [self.webViewEngine evaluateScript:jsString];
            
        }else{
            [self performSelectorOnMainThread:@selector(callBackMethod:) withObject:jsString waitUntilDone:NO];
        }
        return NO;
    }
    @autoreleasepool {
        // 读取被加密文件对应的数据
        NSData *dataEncoded = [NSData dataWithContentsOfFile:filePath];
        // 对NSData进行base64解码
        NSData *dataDecode = [UexEMMGTMBase64 decodeData:dataEncoded];
        
        // 对前1000位进行异或处理
        unsigned char * cByte = (unsigned char*)[dataDecode bytes];
        for (int index = 0; (index < [dataDecode length]) && (index < Key_Count); index++, cByte++)
        {
            *cByte = (*cByte) ^ arrayForEncode[index];
        }
         NSLog(@"解密成功");
        NSLog(@"解密路径============== %@",newFilePath);
        return [dataDecode writeToFile:newFilePath atomically:YES];
    }
}

-(BOOL)func_encodeFile:(NSString *)filePath withNewName:(NSString*)newFilePath {
    if (nil == filePath || NO == [[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        return NO;
    }
    @autoreleasepool {
        //文件路径转换为NSData
        NSData *imageDataOrigin = [NSData dataWithContentsOfFile:filePath];
        // 对前1000位进行异或处理
        unsigned char * cByte = (unsigned char*)[imageDataOrigin bytes];
        for (int index = 0; (index < [imageDataOrigin length]) && (index < Key_Count); index++, cByte++)
        {
            *cByte = (*cByte) ^ arrayForEncode[index];
        }
        
        //对NSData进行base64编码
        NSData *imageDataEncode = [UexEMMGTMBase64 encodeData:imageDataOrigin];
         NSLog(@"加密成功");
        NSLog(@"=================%@",newFilePath);
        return [imageDataEncode writeToFile:newFilePath atomically:YES];
        
       
    }
}

/**
 *回调方法
 \jsString 回调的js
 */
-(void)callBackMethod:(NSString *)jsString{
    
   // [self.meBrwView stringByEvaluatingJavaScriptFromString:jsString];
    [self.webViewEngine evaluateScript:jsString];
}

////原生异步回调JS给网页
//- (void)doCallback:(NSMutableArray *)inArguments{
//    NSDictionary *dict = @{
//                           @"key":@"value"
//                           };
//    //ac_JSONFragment 方法，可以将NSDictionary转换成JSON字符串
//    [self.webViewEngine callbackWithFunctionKeyPath:@"uexPDFReader.cbDoCallback"
//                                          arguments:ACArgsPack(dict.ac_JSONFragment)
//                                         completion:^(JSValue * _Nullable returnValue) {
//                                             if (returnValue) {
//                                                 ACLogDebug(@"回调成功!");
//                                             }
//                                         }];
//}


- (void)openView:(NSMutableArray *)inArguments{
    ACArgsUnpack(NSDictionary *info,ACJSFunctionRef *callback) = inArguments;
    
    //这里是为了防止前端在某些框架的影响下，多次调用同一方法导致崩溃
    if (self.pdfView) {
        return;
    }

    CGSize screenSize = [UIScreen mainScreen].bounds.size;
    NSNumber *xNumber = numberArg(info[@"x"]);
    NSNumber *yNumber = numberArg(info[@"y"]);
    NSNumber *widthNumber = numberArg(info[@"width"]);
    NSNumber *heightNumber = numberArg(info[@"height"]);
    NSString *path = stringArg(info[@"path"]);
    UEX_PARAM_GUARD_NOT_NIL(path);
    NSString *absPath = [self absPath:path];
    BOOL scrollWithWeb = [numberArg(info[@"scrollWithWeb"]) boolValue];
    CGFloat x = xNumber ? xNumber.floatValue : 0;
    CGFloat y = yNumber ? yNumber.floatValue : 0;
    CGFloat width = widthNumber ? widthNumber.floatValue : screenSize.width;
    CGFloat height = heightNumber ? heightNumber.floatValue : screenSize.height;
    if (!self.pdfView) {
        self.pdfView = [[UIWebView alloc] init];
        self.pdfView.scalesPageToFit = YES;
    }
    
    self.pdfView.frame = CGRectMake(x, y, width, height);
    [self.pdfView loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:absPath]]];
    self.pdfView.delegate = self;
    [callback executeWithArguments: ACArgsPack(@(1))];

    if (scrollWithWeb) {
        [[self.webViewEngine webScrollView] addSubview:self.pdfView];
    }else{
        [[self.webViewEngine webView] addSubview:self.pdfView];
    }
    
}


- (void)closeView:(NSMutableArray *)inArguments{
    [self.pdfView removeFromSuperview];
    self.pdfView.delegate = nil;
    self.pdfView = nil;
}


- (void)dismissReaderViewController:(ReaderViewController *)viewController{
    [self close:nil];
    
}

- (void)close:(NSMutableArray *)inArguments{
    [self.readerController dismissViewControllerAnimated:YES completion:nil];
    self.readerController.delegate = nil;
    self.readerController = nil;
}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType
{
//    NSLog(@"%ld",(long)navigationType);
    return YES;
}
- (void)webViewDidFinishLoad:(UIWebView *)webView
{
    
    if (webView.isLoading) {
        
        
        return;
    }
}
- (void)webViewDidStartLoad:(UIWebView *)webView
{
//    NSLog(@"webViewDidStartLoad");
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
//    NSLog(@"didFailLoadWithError");
}

- (void)clean{
    [self close:nil];
    [self closeView:nil];
}

- (void)dealloc{
    [self clean];
}

@end
