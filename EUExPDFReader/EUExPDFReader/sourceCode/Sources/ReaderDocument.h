//
//	ReaderDocument.h
//	Reader v2.5.4
//
//	Created by asdkios on 2013-03-20.
//	Copyright © 2013-2014 asdkios. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ReaderDocument : NSObject <NSCoding>
{
@private // Instance variables

	NSString *_guid;

	NSDate *_fileDate;

	NSDate *_lastOpen;

	NSNumber *_fileSize;

	NSNumber *_pageCount;

	NSNumber *_pageNumber;

	NSMutableIndexSet *_bookmarks;

	NSString *_fileName;

	NSString *_password;

	NSURL *_fileURL;
}

@property (nonatomic, retain, readonly) NSString *guid;
@property (nonatomic, retain, readonly) NSDate *fileDate;
@property (nonatomic, retain, readwrite) NSDate *lastOpen;
@property (nonatomic, retain, readonly) NSNumber *fileSize;
@property (nonatomic, retain, readonly) NSNumber *pageCount;
@property (nonatomic, retain, readwrite) NSNumber *pageNumber;
@property (nonatomic, retain, readonly) NSMutableIndexSet *bookmarks;
@property (nonatomic, retain, readonly) NSString *fileName;
@property (nonatomic, retain, readonly) NSString *password;
@property (nonatomic, retain, readonly) NSURL *fileURL;

+ (ReaderDocument *)withDocumentFilePath:(NSString *)filename password:(NSString *)phrase;

+ (ReaderDocument *)unarchiveFromFileName:(NSString *)filename password:(NSString *)phrase;

+ (NSString *)GUID;

- (id)initWithFilePath:(NSString *)fullFilePath password:(NSString *)phrase;

- (void)saveReaderDocument;

- (void)updateProperties;

@end
