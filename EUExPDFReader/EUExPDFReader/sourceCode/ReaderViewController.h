//
//	ReaderViewController.h
//	Reader v2.5.4
//
//	Created by asdkios on 2013-03-20.
//	Copyright © 2013-2014 asdkios. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <MessageUI/MessageUI.h>

#import "ReaderDocument.h"
#import "ReaderContentView.h"
#import "ReaderMainToolbar.h"
#import "ReaderMainPagebar.h"
#import "ThumbsViewController.h"


@class ReaderViewController;
@class ReaderMainToolbar;
@class EUExPDFReader;

@protocol ReaderViewControllerDelegate <NSObject>

@optional // Delegate protocols

- (void)dismissReaderViewController:(ReaderViewController *)viewController;

@end

@interface ReaderViewController : UIViewController <UIScrollViewDelegate, UIGestureRecognizerDelegate, MFMailComposeViewControllerDelegate,
													ReaderMainToolbarDelegate, ReaderMainPagebarDelegate, ReaderContentViewDelegate,
													ThumbsViewControllerDelegate>
{
@private // Instance variables

	ReaderDocument *document;

	UIScrollView *theScrollView;

	ReaderMainToolbar *mainToolbar;

	ReaderMainPagebar *mainPagebar;

	NSMutableDictionary *contentViews;

	UIPrintInteractionController *printInteraction;

	NSInteger currentPage;

	CGSize lastAppearSize;

	NSDate *lastHideTime;

	BOOL isVisible;
}
//@property(nonatomic,weak) EUExPDFReader *uexObj;
@property (nonatomic, assign, readwrite) id <ReaderViewControllerDelegate> delegate;


- (id)initWithReaderDocument:(ReaderDocument *)object withEUExObj:(EUExPDFReader *)euexPDFReader;

- (instancetype)initWithEUExObj:(EUExPDFReader *)euexPDFReader;

@end
