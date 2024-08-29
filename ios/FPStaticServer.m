#import "FPStaticServer.h"
#import <CommonCrypto/CommonCrypto.h>
#import <GCDWebServer/GCDWebServer.h>
#import <GCDWebServer/GCDWebServerDataResponse.h>
#import <Foundation/Foundation.h>

@implementation FPStaticServer

@synthesize bridge = _bridge;

RCT_EXPORT_MODULE();

- (instancetype)init {
    if ((self = [super init])) {
        [GCDWebServer self];
        _webServer = [[GCDWebServer alloc] init];
    }
    return self;
}

- (void)dealloc {
    if (_webServer.isRunning == YES) {
        [_webServer stop];
    }
    _webServer = nil;
}

- (dispatch_queue_t)methodQueue {
    return dispatch_queue_create("com.futurepress.staticserver", DISPATCH_QUEUE_SERIAL);
}

- (NSString *)sha256HashOfString:(NSString *)input {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }
    
    return output;
}

// AES-256 Decryption Method
- (NSData *)aes256Decrypt:(NSData *)data key:(NSData *)key iv:(NSData *)iv {
    NSMutableData *decryptedData = [NSMutableData dataWithLength:data.length];
    size_t numBytesDecrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        key.bytes,
        kCCKeySizeAES256,
        iv.bytes,
        data.bytes,
        data.length,
        decryptedData.mutableBytes,
        decryptedData.length,
        &numBytesDecrypted
    );
    
    if (cryptStatus == kCCSuccess) {
        decryptedData.length = numBytesDecrypted;
        return decryptedData;
    } else {
        NSLog(@"Decryption failed with status: %d", cryptStatus);
        return nil;
    }
}

- (NSString *)mimeTypeForFileAtPath:(NSString *)filePath {
    NSString *fileExtension = [filePath pathExtension];
    NSDictionary *mimeTypes = @{
        @"html": @"text/html",
        @"htm": @"text/html",
        @"xml": @"application/xml",
        @"js": @"application/javascript",
        @"css": @"text/css",
        @"jpg": @"image/jpeg",
        @"jpeg": @"image/jpeg",
        @"png": @"image/png",
        @"gif": @"image/gif",
        @"pdf": @"application/pdf",
        @"json": @"application/json",
        // Add more mappings as needed
    };

    NSString *mimeType = mimeTypes[fileExtension.lowercaseString];
    if (!mimeType) {
        mimeType = @"application/octet-stream"; // Default MIME type for unknown files
    }
    return mimeType;
}

// Convert NSData to UTF8 String
- (NSString *)stringFromData:(NSData *)data {
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

RCT_EXPORT_METHOD(start: (NSString *)port
                  root:(NSString *)optroot
                  localOnly:(BOOL *)localhost_only
                  keepAlive:(BOOL *)keep_alive
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *root;

    if ([optroot isEqualToString:@"DocumentDir"]) {
        root = [NSString stringWithFormat:@"%@", [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0]];
    } else if ([optroot isEqualToString:@"BundleDir"]) {
        root = [NSString stringWithFormat:@"%@", [[NSBundle mainBundle] bundlePath]];
    } else if ([optroot hasPrefix:@"/"]) {
        root = optroot;
    } else {
        root = [NSString stringWithFormat:@"%@/%@", [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0], optroot];
    }

    if (root && [root length] > 0) {
        self.www_root = root;
    }

    if (port && [port length] > 0) {
        NSNumberFormatter *f = [[NSNumberFormatter alloc] init];
        f.numberStyle = NSNumberFormatterDecimalStyle;
        self.port = [f numberFromString:port];
    } else {
        self.port = [NSNumber numberWithInt:-1];
    }

    self.keep_alive = keep_alive;
    self.localhost_only = localhost_only;

    if (_webServer.isRunning != NO) {
        NSLog(@"StaticServer already running at %@", self.url);
        resolve(self.url);
        return;
    }

    NSString *basePath = @"/";
    NSString *indexFilename = @"index.html";
    NSUInteger cacheAge = 3600;
    BOOL allowRangeRequests = YES;

    [_webServer addHandlerWithMatchBlock:^GCDWebServerRequest*(NSString *requestMethod, NSURL *requestURL, NSDictionary<NSString*, NSString*> *requestHeaders, NSString *urlPath, NSDictionary<NSString*, NSString*> *urlQuery) {
        NSLog(@"URL: %@", requestURL);

        NSString *relativePath = [requestURL path];
        NSString *queryString = [requestURL query];

        NSString *cleanedPath = [relativePath hasPrefix:@"/"] ? [relativePath substringFromIndex:1] : relativePath;
        NSString *urlString = [NSString stringWithFormat:@"%@%@", cleanedPath, queryString ? [NSString stringWithFormat:@"?%@", queryString] : @""];
        
        // Append the prefix and hash the URL
        NSString *prefixedURLString = [NSString stringWithFormat:@"787-9-P-GE/%@", urlString];
        NSString *hashedURL = [self sha256HashOfString:prefixedURLString];

        NSLog(@"SHA-256 Hash of URL: %@", hashedURL);

        // Store the hashed file path
        NSString *filePath = [self.www_root stringByAppendingPathComponent:hashedURL];
        NSLog(@"File Path: %@", filePath);

        if (![requestMethod isEqualToString:@"GET"]) {
            return nil;
        }
        return [[GCDWebServerRequest alloc] initWithMethod:requestMethod url:requestURL headers:requestHeaders path:urlPath query:urlQuery];
    } processBlock:^GCDWebServerResponse*(GCDWebServerRequest *request) {
        NSString *relativePath = [request.path substringFromIndex:@"/".length];
        NSString *prefixedURLString = [NSString stringWithFormat:@"787-9-P-GE/%@", relativePath];
        NSString *hashedURL = [self sha256HashOfString:prefixedURLString];
        NSString *filePath = [self.www_root stringByAppendingPathComponent:hashedURL];
        NSLog(@"File Path from Hash: %@", filePath);

        NSError *fileError;
        NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:filePath error:&fileError];
        if (fileError) {
            NSLog(@"Error getting file attributes: %@", fileError);
            return [GCDWebServerResponse responseWithStatusCode:kGCDWebServerHTTPStatusCode_NotFound];
        }
        
        NSString *fileType = [attributes fileType];
        NSLog(@"fileType: %@", fileType);

        if ([fileType isEqualToString:NSFileTypeDirectory]) {
            if (indexFilename) {
                NSString *indexPath = [filePath stringByAppendingPathComponent:indexFilename];
                NSDictionary *indexAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:indexPath error:&fileError];
                if (fileError) {
                    NSLog(@"Error getting index file attributes: %@", fileError);
                    return [GCDWebServerResponse responseWithStatusCode:kGCDWebServerHTTPStatusCode_NotFound];
                }
                
                NSString *indexType = [indexAttributes fileType];
                if ([indexType isEqualToString:NSFileTypeRegular]) {
                    return [GCDWebServerFileResponse responseWithFile:indexPath];
                }
            }
            return [GCDWebServerResponse responseWithStatusCode:kGCDWebServerHTTPStatusCode_NotFound];
        } else if ([fileType isEqualToString:NSFileTypeRegular]) {
            NSData *fileData = [NSData dataWithContentsOfFile:filePath];
            if (fileData) {
                NSData *key = [self dataWithHexString:@"0000000000000000000000000000000000000000000000000000000000000000"];
                NSData *iv = [self dataWithHexString:@"00000000000000000000000000000000"];
                NSData *decryptedData = [self aes256Decrypt:fileData key:key iv:iv];
                if (decryptedData) {
                    NSLog(@"filePath>: %@", filePath);
                    NSString *contentType = [self mimeTypeForFileAtPath:prefixedURLString];
                    NSLog(@"contentType: %@", contentType);
                    if ([contentType isEqualToString:@"text/html"] || [contentType isEqualToString:@"application/xml"] || [contentType isEqualToString:@"application/json"] || [contentType isEqualToString:@"text/css"] || [contentType isEqualToString:@"application/javascript"]) {
                        // Convert to string for text-based file types
                        NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
                        NSLog(@"decryptedString: %@", decryptedString);
                        if (decryptedString) {
                            GCDWebServerDataResponse *response = [GCDWebServerDataResponse responseWithData:decryptedData contentType:contentType];
                            [response setValue:@"no-cache" forAdditionalHeader:@"Cache-Control"];
                            [response setValue:@"GET" forAdditionalHeader:@"Access-Control-Request-Method"];
                            [response setValue:@"OriginX-Requested-With, Content-Type, Accept, Cache-Control, Range,Access-Control-Allow-Origin" forAdditionalHeader:@"Access-Control-Request-Headers"];
                            [response setValue:@"*" forAdditionalHeader:@"Access-Control-Allow-Origin"];
                            return response;
                        }
                    } else {
                        // For binary files, serve as is
                        GCDWebServerDataResponse *response = [GCDWebServerDataResponse responseWithData:decryptedData contentType:contentType];
                        [response setValue:@"no-cache" forAdditionalHeader:@"Cache-Control"];
                        [response setValue:@"GET" forAdditionalHeader:@"Access-Control-Request-Method"];
                        [response setValue:@"OriginX-Requested-With, Content-Type, Accept, Cache-Control, Range,Access-Control-Allow-Origin" forAdditionalHeader:@"Access-Control-Request-Headers"];
                        [response setValue:@"*" forAdditionalHeader:@"Access-Control-Allow-Origin"];
                        return response;
                    }
                }
            }
        }
        return [GCDWebServerResponse responseWithStatusCode:kGCDWebServerHTTPStatusCode_NotFound];
    }];

    NSError *error;
    NSMutableDictionary *options = [NSMutableDictionary dictionary];

    NSLog(@"Started StaticServer on port %@", self.port);

    if (![self.port isEqualToNumber:[NSNumber numberWithInt:-1]]) {
        [options setObject:self.port forKey:GCDWebServerOption_Port];
    } else {
        [options setObject:[NSNumber numberWithInteger:8080] forKey:GCDWebServerOption_Port];
    }

    if (self.localhost_only == YES) {
        [options setObject:@(YES) forKey:GCDWebServerOption_BindToLocalhost];
    }

    if (self.keep_alive == YES) {
        [options setObject:@(NO) forKey:GCDWebServerOption_AutomaticallySuspendInBackground];
        [options setObject:@2.0 forKey:GCDWebServerOption_ConnectedStateCoalescingInterval];
    }

    if ([_webServer startWithOptions:options error:&error]) {
        NSNumber *listenPort = [NSNumber numberWithUnsignedInteger:_webServer.port];
        self.port = listenPort;

        if (_webServer.serverURL == NULL) {
            reject(@"server_error", @"StaticServer could not start", error);
        } else {
            self.url = [NSString stringWithFormat:@"%@://%@:%@", [_webServer.serverURL scheme], [_webServer.serverURL host], [_webServer.serverURL port]];
            NSLog(@"Started StaticServer at URL %@", self.url);
            resolve(self.url);
        }
    } else {
        NSLog(@"Error starting StaticServer: %@", error);
        reject(@"server_error", @"StaticServer could not start", error);
    }
}

- (NSData *)dataWithHexString:(NSString *)hexString {
    NSMutableData *data = [NSMutableData data];
    for (NSUInteger i = 0; i < [hexString length]; i += 2) {
        NSString *hexChar = [hexString substringWithRange:NSMakeRange(i, 2)];
        unsigned int intValue;
        [[NSScanner scannerWithString:hexChar] scanHexInt:&intValue];
        [data appendBytes:&intValue length:1];
    }
    return data;
}

RCT_EXPORT_METHOD(stop) {
    if (_webServer.isRunning == YES) {
        [_webServer stop];
        NSLog(@"StaticServer stopped");
    }
}

RCT_EXPORT_METHOD(origin:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    if (_webServer.isRunning == YES) {
        resolve(self.url);
    } else {
        resolve(@"");
    }
}

RCT_EXPORT_METHOD(isRunning:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    bool isRunning = _webServer != nil && _webServer.isRunning == YES;
    resolve(@(isRunning));
}

+ (BOOL)requiresMainQueueSetup {
    return YES;
}

@end