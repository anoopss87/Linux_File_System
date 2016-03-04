/* Digital Forensics - Spring 2016 
 * 
 * common.h - common structures and functions are declared in this file.
 * @author - Anoop S Somashekar
*/

#include <sys/stat.h>
#include <errno.h>
#include <linux/hdreg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <sys/types.h>
#include <string.h>
#include <inttypes.h>

#define SUPER_BLOCK_OFFSET 1024
#define SUPER_BLOCK_SIZE 1024
#define BLOCK_SIZE_VALUE_OFFSET 24
#define NUM_OF_BLOCKS_IN_A_GROUP_REL_OFFSET 24
#define NUM_OF_INODES_IN_A_GROUP_REL_OFFSET 4
#define MIN_BLOCK_SIZE 1024
#define BLOCK_GROUP_DESC_SIZE 32

//global variable so that it can be reused
int blockSize;
int blockGroupCount;

typedef signed char _s8;
typedef unsigned char _u8;
typedef unsigned char byte;

typedef signed short _s16;
typedef unsigned short _u16;

typedef signed long _s32;
typedef unsigned long _u32;

typedef long long _s64;
typedef unsigned long long _u64;

/*
 * Structure of a blocks group descriptor
*/
struct ext3_group_desc
{
	_u32	bg_block_bitmap;		/* Blocks bitmap block */
	_u32	bg_inode_bitmap;		/* Inodes bitmap block */
	_u32	bg_inode_table;		/* Inodes table block */
	_u16	bg_free_blocks_count;	/* Free blocks count */
	_u16	bg_free_inodes_count;	/* Free inodes count */
	_u16	bg_used_dirs_count;	/* Directories count */
	_u16	bg_pad;
	_u32	bg_reserved[3];
};

//Function declaration
int max(int a, int b);
int getBlockSize(char driveName[]);
int getNumberofBlockGroups(char driveName[]);
int isPowerOf3_5_7(int number);
long long getGroupDescStartOffset(int index);
