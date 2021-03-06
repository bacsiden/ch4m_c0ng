USE [DB_9CF750_db]
GO
/****** Object:  Table [dbo].[fwMenu]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[fwMenu](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Title] [nvarchar](100) NOT NULL,
	[ParentID] [int] NULL,
	[Url] [nvarchar](255) NULL,
	[Icon] [nvarchar](50) NULL,
	[Order] [int] NULL,
	[Actived] [bit] NULL,
	[SubAction] [varchar](100) NULL,
 CONSTRAINT [PK_Module] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET ANSI_PADDING OFF
GO
SET IDENTITY_INSERT [dbo].[fwMenu] ON
INSERT [dbo].[fwMenu] ([ID], [Title], [ParentID], [Url], [Icon], [Order], [Actived], [SubAction]) VALUES (1, N'Group', 5, N'/WebLib/ListGroup', NULL, 1, 1, NULL)
INSERT [dbo].[fwMenu] ([ID], [Title], [ParentID], [Url], [Icon], [Order], [Actived], [SubAction]) VALUES (5, N'Quản trị hệ thống', NULL, N'/', NULL, 0, 1, NULL)
INSERT [dbo].[fwMenu] ([ID], [Title], [ParentID], [Url], [Icon], [Order], [Actived], [SubAction]) VALUES (9, N'Left menu', 5, N'/WebLib/ListMenu', NULL, 5, 1, NULL)
INSERT [dbo].[fwMenu] ([ID], [Title], [ParentID], [Url], [Icon], [Order], [Actived], [SubAction]) VALUES (44, N'Top menu', 0, N'/TopMenu/Index', NULL, 1, 1, NULL)
INSERT [dbo].[fwMenu] ([ID], [Title], [ParentID], [Url], [Icon], [Order], [Actived], [SubAction]) VALUES (51, N'Phiếu yêu cầu', 0, N'/Ticket/Index', NULL, -1, 1, NULL)
INSERT [dbo].[fwMenu] ([ID], [Title], [ParentID], [Url], [Icon], [Order], [Actived], [SubAction]) VALUES (55, N'Constant', NULL, N'/Constant/index', NULL, 3, 0, NULL)
INSERT [dbo].[fwMenu] ([ID], [Title], [ParentID], [Url], [Icon], [Order], [Actived], [SubAction]) VALUES (56, N'Bộ phận', 0, N'/Dept/Index', NULL, 1, 1, NULL)
INSERT [dbo].[fwMenu] ([ID], [Title], [ParentID], [Url], [Icon], [Order], [Actived], [SubAction]) VALUES (61, N'User', 5, N'/WebLib/ListUser', NULL, 0, 1, NULL)
SET IDENTITY_INSERT [dbo].[fwMenu] OFF
/****** Object:  Table [dbo].[fwHtmlPage]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[fwHtmlPage](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[KeyUrl] [varchar](100) NOT NULL,
	[Content] [nvarchar](max) NULL,
 CONSTRAINT [PK_HtmlPage] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
SET ANSI_PADDING OFF
GO
SET IDENTITY_INSERT [dbo].[fwHtmlPage] ON
INSERT [dbo].[fwHtmlPage] ([ID], [KeyUrl], [Content]) VALUES (1, N'gioi-thieu', N'<h2><em>Giới thiệu về Shop CNC</em></h2>
')
INSERT [dbo].[fwHtmlPage] ([ID], [KeyUrl], [Content]) VALUES (2, N'download', N'<p><font color="#006400"><strong>Đặt c&aacute;c link download ở đ&acirc;y</strong></font></p>
')
SET IDENTITY_INSERT [dbo].[fwHtmlPage] OFF
/****** Object:  Table [dbo].[fwGroup]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[fwGroup](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Title] [nvarchar](50) NOT NULL,
 CONSTRAINT [PK_Group] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[fwGroup] ON
INSERT [dbo].[fwGroup] ([ID], [Title]) VALUES (1, N'System management')
INSERT [dbo].[fwGroup] ([ID], [Title]) VALUES (2, N'Normal user')
INSERT [dbo].[fwGroup] ([ID], [Title]) VALUES (4, N'Nhóm 2')
SET IDENTITY_INSERT [dbo].[fwGroup] OFF
/****** Object:  Table [dbo].[fwConfig]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[fwConfig](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Key] [varchar](50) NOT NULL,
	[Title] [nvarchar](500) NULL,
	[Type] [varchar](20) NULL,
	[Choise] [nvarchar](200) NULL,
 CONSTRAINT [PK_Config] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET ANSI_PADDING OFF
GO
SET IDENTITY_INSERT [dbo].[fwConfig] ON
INSERT [dbo].[fwConfig] ([ID], [Key], [Title], [Type], [Choise]) VALUES (1, N'FTPServer', N'ftp://ftp.Smarterasp.net', N'0', NULL)
INSERT [dbo].[fwConfig] ([ID], [Key], [Title], [Type], [Choise]) VALUES (2, N'FTPUser', N'ezsure-001', N'0', NULL)
SET IDENTITY_INSERT [dbo].[fwConfig] OFF
/****** Object:  Table [dbo].[Checkout]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Checkout](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Created] [datetime] NOT NULL,
	[CreatedBy] [int] NOT NULL,
	[No] [nvarchar](20) NULL,
	[Ben] [nvarchar](500) NOT NULL,
	[DeptID] [int] NOT NULL,
	[PaymentMethod] [int] NULL,
	[PaymentDate] [datetime] NOT NULL,
	[SumTotal] [money] NOT NULL,
	[AdvandPayment] [money] NULL,
	[BankingCharge] [money] NULL,
	[Total] [money] NOT NULL,
	[InWords] [nvarchar](500) NULL,
	[OnExpenses] [int] NULL,
	[Track] [nvarchar](500) NOT NULL,
	[Current] [int] NOT NULL,
	[Director] [int] NULL,
	[InternalControl] [int] NULL,
	[ChkFeedbackID] [int] NULL,
	[Status] [int] NOT NULL,
 CONSTRAINT [PK_CheckoutID] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Dept]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Dept](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Title] [nvarchar](100) NOT NULL,
	[GroupID] [int] NOT NULL,
	[LeaderUserID] [int] NULL,
 CONSTRAINT [PK_Dept] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[Dept] ON
INSERT [dbo].[Dept] ([ID], [Title], [GroupID], [LeaderUserID]) VALUES (1, N'Bộ phận 1', 1, 23)
INSERT [dbo].[Dept] ([ID], [Title], [GroupID], [LeaderUserID]) VALUES (2, N'Motion số 1 đông nam á', 1, NULL)
SET IDENTITY_INSERT [dbo].[Dept] OFF
/****** Object:  Table [dbo].[fwRole]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[fwRole](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Title] [nvarchar](255) NOT NULL,
	[Code] [varchar](20) NOT NULL,
 CONSTRAINT [RoleSys] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET ANSI_PADDING OFF
GO
SET IDENTITY_INSERT [dbo].[fwRole] ON
INSERT [dbo].[fwRole] ([ID], [Title], [Code]) VALUES (1, N'System managerment', N'Super')
INSERT [dbo].[fwRole] ([ID], [Title], [Code]) VALUES (4, N'Normal users', N'xxx')
SET IDENTITY_INSERT [dbo].[fwRole] OFF
/****** Object:  Table [dbo].[fwUser]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[fwUser](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[AspnetUserID] [nvarchar](50) NULL,
	[UserName] [varchar](50) NOT NULL,
	[Name] [nvarchar](50) NULL,
	[PhoneNumber] [varchar](20) NULL,
	[Email] [nvarchar](100) NULL,
	[Sex] [nvarchar](20) NULL,
	[Birthday] [datetime] NULL,
	[Address] [nvarchar](200) NULL,
	[Status] [int] NOT NULL,
	[Locked] [bit] NOT NULL,
	[Avata] [nvarchar](50) NULL,
	[NotiCount] [int] NULL,
	[Pass] [nvarchar](50) NULL,
 CONSTRAINT [PK_Account] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET ANSI_PADDING OFF
GO
SET IDENTITY_INSERT [dbo].[fwUser] ON
INSERT [dbo].[fwUser] ([ID], [AspnetUserID], [UserName], [Name], [PhoneNumber], [Email], [Sex], [Birthday], [Address], [Status], [Locked], [Avata], [NotiCount], [Pass]) VALUES (23, N'012CD2E0-D9E8-4C91-B894-8E1BF03A7D96', N'admin', N'Nguyễn Duy Khánh', N'32456576', N'duykhanh.sctn@gmail.com', NULL, CAST(0x0000A38100000000 AS DateTime), N'Thái Nguyên', 0, 0, NULL, NULL, NULL)
INSERT [dbo].[fwUser] ([ID], [AspnetUserID], [UserName], [Name], [PhoneNumber], [Email], [Sex], [Birthday], [Address], [Status], [Locked], [Avata], [NotiCount], [Pass]) VALUES (32, NULL, N'duykhanh', N'Great Man', NULL, N'duykhanh.sctn@gmail.com', NULL, NULL, NULL, 0, 0, NULL, 0, NULL)
SET IDENTITY_INSERT [dbo].[fwUser] OFF
/****** Object:  Table [dbo].[Ticket]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[Ticket](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Type] [int] NOT NULL,
	[Created] [datetime] NOT NULL,
	[CreatedBy] [int] NOT NULL,
	[DeptID] [int] NOT NULL,
	[Track] [varchar](100) NOT NULL,
	[Current] [int] NOT NULL,
	[Status] [int] NOT NULL,
	[FilePath] [nvarchar](1000) NULL,
	[PassedBy] [int] NULL,
	[ApprovedBy] [int] NULL,
 CONSTRAINT [PK_Ticket] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET ANSI_PADDING OFF
GO
SET IDENTITY_INSERT [dbo].[Ticket] ON
INSERT [dbo].[Ticket] ([ID], [Type], [Created], [CreatedBy], [DeptID], [Track], [Current], [Status], [FilePath], [PassedBy], [ApprovedBy]) VALUES (1, 0, CAST(0x0000A4E5000ED9C6 AS DateTime), 23, 1, N'23#;', 23, 4, NULL, NULL, NULL)
INSERT [dbo].[Ticket] ([ID], [Type], [Created], [CreatedBy], [DeptID], [Track], [Current], [Status], [FilePath], [PassedBy], [ApprovedBy]) VALUES (2, 0, CAST(0x0000A4E5015DD7D7 AS DateTime), 23, 1, N'23#;', 23, 4, NULL, NULL, NULL)
SET IDENTITY_INSERT [dbo].[Ticket] OFF
/****** Object:  Table [dbo].[TicketUser]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TicketUser](
	[UserID] [int] NOT NULL,
	[TicketID] [int] NOT NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TicketDetails]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TicketDetails](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[TicketID] [int] NOT NULL,
	[Title] [nvarchar](500) NOT NULL,
	[Quantity] [int] NOT NULL,
	[Reason] [nvarchar](500) NULL,
	[DateRequire] [datetime] NOT NULL,
 CONSTRAINT [PK_TicketID] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[TicketDetails] ON
INSERT [dbo].[TicketDetails] ([ID], [TicketID], [Title], [Quantity], [Reason], [DateRequire]) VALUES (1, 1, N'dien gai 1', 1, N'sdafsdf', CAST(0x0000A4E600000000 AS DateTime))
INSERT [dbo].[TicketDetails] ([ID], [TicketID], [Title], [Quantity], [Reason], [DateRequire]) VALUES (2, 1, N'dien gai 2', 2, N'sdafsdf', CAST(0x0000A4E700000000 AS DateTime))
INSERT [dbo].[TicketDetails] ([ID], [TicketID], [Title], [Quantity], [Reason], [DateRequire]) VALUES (3, 2, N'Mua máy in', 1, N'Mục đích là no mục đích', CAST(0x0000A4E600000000 AS DateTime))
INSERT [dbo].[TicketDetails] ([ID], [TicketID], [Title], [Quantity], [Reason], [DateRequire]) VALUES (4, 2, N'Mua thiết bị điều hòa', 10, N'Mục đích là no mục đích', CAST(0x0000A4E600000000 AS DateTime))
SET IDENTITY_INSERT [dbo].[TicketDetails] OFF
/****** Object:  Table [dbo].[fwUserGroup]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[fwUserGroup](
	[GroupID] [int] NOT NULL,
	[UserID] [int] NOT NULL,
 CONSTRAINT [PK_UserInGroup] PRIMARY KEY CLUSTERED 
(
	[GroupID] ASC,
	[UserID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
INSERT [dbo].[fwUserGroup] ([GroupID], [UserID]) VALUES (1, 23)
INSERT [dbo].[fwUserGroup] ([GroupID], [UserID]) VALUES (2, 23)
INSERT [dbo].[fwUserGroup] ([GroupID], [UserID]) VALUES (4, 23)
/****** Object:  Table [dbo].[fwRoleGroup]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[fwRoleGroup](
	[GroupID] [int] NOT NULL,
	[RoleID] [int] NOT NULL,
 CONSTRAINT [PK_RoleInGroup] PRIMARY KEY CLUSTERED 
(
	[GroupID] ASC,
	[RoleID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
INSERT [dbo].[fwRoleGroup] ([GroupID], [RoleID]) VALUES (1, 1)
INSERT [dbo].[fwRoleGroup] ([GroupID], [RoleID]) VALUES (1, 4)
INSERT [dbo].[fwRoleGroup] ([GroupID], [RoleID]) VALUES (2, 1)
INSERT [dbo].[fwRoleGroup] ([GroupID], [RoleID]) VALUES (2, 4)
INSERT [dbo].[fwRoleGroup] ([GroupID], [RoleID]) VALUES (4, 1)
INSERT [dbo].[fwRoleGroup] ([GroupID], [RoleID]) VALUES (4, 4)
/****** Object:  Table [dbo].[fwMenuRole]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[fwMenuRole](
	[MenuID] [int] NOT NULL,
	[RoleID] [int] NOT NULL,
 CONSTRAINT [PK_mMenuInRole] PRIMARY KEY CLUSTERED 
(
	[MenuID] ASC,
	[RoleID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
INSERT [dbo].[fwMenuRole] ([MenuID], [RoleID]) VALUES (1, 1)
INSERT [dbo].[fwMenuRole] ([MenuID], [RoleID]) VALUES (5, 1)
/****** Object:  Table [dbo].[ChkFeedback]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ChkFeedback](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[CheckoutID] [int] NOT NULL,
	[Title] [nvarchar](500) NOT NULL,
	[UserID] [int] NOT NULL,
	[Created] [datetime] NOT NULL,
 CONSTRAINT [PK_ChkFeedbackID] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[CheckoutDetails]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CheckoutDetails](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[CheckoutID] [int] NOT NULL,
	[Title] [nvarchar](500) NOT NULL,
	[VND] [money] NOT NULL,
	[USD] [money] NULL,
	[EUR] [money] NULL,
 CONSTRAINT [PK_CheckoutDetailsID] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Feedback]    Script Date: 07/31/2015 13:55:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Feedback](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[TicketID] [int] NOT NULL,
	[Title] [nvarchar](500) NOT NULL,
	[UserID] [int] NOT NULL,
	[Created] [datetime] NOT NULL,
 CONSTRAINT [PK_FeedbackID] PRIMARY KEY CLUSTERED 
(
	[ID] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Default [DF_Config_Multiline]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwConfig] ADD  CONSTRAINT [DF_Config_Multiline]  DEFAULT ((0)) FOR [Type]
GO
/****** Object:  Default [DF_mMenu_IsActive]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwMenu] ADD  CONSTRAINT [DF_mMenu_IsActive]  DEFAULT ((1)) FOR [Actived]
GO
/****** Object:  Default [DF_User_Status]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwUser] ADD  CONSTRAINT [DF_User_Status]  DEFAULT ((0)) FOR [Status]
GO
/****** Object:  Default [DF_User_Locked]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwUser] ADD  CONSTRAINT [DF_User_Locked]  DEFAULT ((0)) FOR [Locked]
GO
/****** Object:  ForeignKey [FK_CheckoutDetails_Checkout]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[CheckoutDetails]  WITH CHECK ADD  CONSTRAINT [FK_CheckoutDetails_Checkout] FOREIGN KEY([CheckoutID])
REFERENCES [dbo].[Checkout] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[CheckoutDetails] CHECK CONSTRAINT [FK_CheckoutDetails_Checkout]
GO
/****** Object:  ForeignKey [FK_ChkFeedback_Checkout]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[ChkFeedback]  WITH CHECK ADD  CONSTRAINT [FK_ChkFeedback_Checkout] FOREIGN KEY([CheckoutID])
REFERENCES [dbo].[Checkout] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[ChkFeedback] CHECK CONSTRAINT [FK_ChkFeedback_Checkout]
GO
/****** Object:  ForeignKey [FK_Feedback_Ticket]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[Feedback]  WITH CHECK ADD  CONSTRAINT [FK_Feedback_Ticket] FOREIGN KEY([TicketID])
REFERENCES [dbo].[Ticket] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[Feedback] CHECK CONSTRAINT [FK_Feedback_Ticket]
GO
/****** Object:  ForeignKey [FK_fwMenuRole_fwRole]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwMenuRole]  WITH CHECK ADD  CONSTRAINT [FK_fwMenuRole_fwRole] FOREIGN KEY([RoleID])
REFERENCES [dbo].[fwRole] ([ID])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[fwMenuRole] CHECK CONSTRAINT [FK_fwMenuRole_fwRole]
GO
/****** Object:  ForeignKey [FK_mMenuInRole_mMenu]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwMenuRole]  WITH CHECK ADD  CONSTRAINT [FK_mMenuInRole_mMenu] FOREIGN KEY([MenuID])
REFERENCES [dbo].[fwMenu] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[fwMenuRole] CHECK CONSTRAINT [FK_mMenuInRole_mMenu]
GO
/****** Object:  ForeignKey [FK_RoleInGroup_Group]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwRoleGroup]  WITH CHECK ADD  CONSTRAINT [FK_RoleInGroup_Group] FOREIGN KEY([GroupID])
REFERENCES [dbo].[fwGroup] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[fwRoleGroup] CHECK CONSTRAINT [FK_RoleInGroup_Group]
GO
/****** Object:  ForeignKey [FK_RoleInGroup_Role1]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwRoleGroup]  WITH CHECK ADD  CONSTRAINT [FK_RoleInGroup_Role1] FOREIGN KEY([RoleID])
REFERENCES [dbo].[fwRole] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[fwRoleGroup] CHECK CONSTRAINT [FK_RoleInGroup_Role1]
GO
/****** Object:  ForeignKey [FK_UserInGroup_Group]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwUserGroup]  WITH CHECK ADD  CONSTRAINT [FK_UserInGroup_Group] FOREIGN KEY([GroupID])
REFERENCES [dbo].[fwGroup] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[fwUserGroup] CHECK CONSTRAINT [FK_UserInGroup_Group]
GO
/****** Object:  ForeignKey [FK_UserInGroup_User]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[fwUserGroup]  WITH CHECK ADD  CONSTRAINT [FK_UserInGroup_User] FOREIGN KEY([UserID])
REFERENCES [dbo].[fwUser] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[fwUserGroup] CHECK CONSTRAINT [FK_UserInGroup_User]
GO
/****** Object:  ForeignKey [FK_TicketDetails_Ticket]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[TicketDetails]  WITH CHECK ADD  CONSTRAINT [FK_TicketDetails_Ticket] FOREIGN KEY([TicketID])
REFERENCES [dbo].[Ticket] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[TicketDetails] CHECK CONSTRAINT [FK_TicketDetails_Ticket]
GO
/****** Object:  ForeignKey [FK_TicketUser_fwUser]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[TicketUser]  WITH CHECK ADD  CONSTRAINT [FK_TicketUser_fwUser] FOREIGN KEY([UserID])
REFERENCES [dbo].[fwUser] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[TicketUser] CHECK CONSTRAINT [FK_TicketUser_fwUser]
GO
/****** Object:  ForeignKey [FK_TicketUser_Ticket]    Script Date: 07/31/2015 13:55:19 ******/
ALTER TABLE [dbo].[TicketUser]  WITH CHECK ADD  CONSTRAINT [FK_TicketUser_Ticket] FOREIGN KEY([TicketID])
REFERENCES [dbo].[Ticket] ([ID])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[TicketUser] CHECK CONSTRAINT [FK_TicketUser_Ticket]
GO
