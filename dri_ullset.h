#ifndef DRI_ULL_SET_H
#define DRI_ULL_SET_H

#ifndef _AMD64_
#define _AMD64_
#endif

#include <ntifs.h>

typedef struct Number {
    ULONGLONG number;
} Number;

typedef struct ULLSet {
    RTL_AVL_TABLE avlTable;
} ULLSet;

static inline RTL_GENERIC_COMPARE_RESULTS NumberCompare(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
)
{
    Number* p1 = (Number*)FirstStruct;
    Number* p2 = (Number*)SecondStruct;

    if (p1->number == p2->number) {
        return GenericEqual;
    } else if (p1->number > p2->number) {
        return GenericGreaterThan;
    }
    return GenericLessThan;
}

static inline PVOID NumberAllocate(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ CLONG ByteSize
)
{
    PVOID pBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, ByteSize, 'SStr');
    if (pBuffer) {
        RtlZeroMemory(pBuffer, ByteSize);
    }
    return pBuffer;
}

static inline VOID NumberFree(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Buffer
)
{
    ExFreePoolWithTag(Buffer, 'SStr');
}

static inline VOID ULLSetInit(ULLSet* ULLSet) {
    RtlInitializeGenericTableAvl(
        &ULLSet->avlTable,
        NumberCompare,
        NumberAllocate,
        NumberFree,
        NULL
    );
}

static inline BOOLEAN ULLSetInsert(ULLSet* ULLSet, ULONGLONG number) {
    Number tempNumber = {0};
    tempNumber.number = number;

    BOOLEAN isNew;
    PVOID pInserted = RtlInsertElementGenericTableAvl(
        &ULLSet->avlTable,
        &tempNumber,
        sizeof(Number),
        &isNew
    );

    return isNew;
}

static inline BOOLEAN ULLSetContains(ULLSet* ULLSet, ULONGLONG number) {
    Number tempNumber = {0};
    tempNumber.number = number;

    PVOID pFound = RtlLookupElementGenericTableAvl(
        &ULLSet->avlTable,
        &tempNumber
    );

    return (pFound != NULL);
}

static inline VOID ULLSetRemove(ULLSet* ULLSet, ULONGLONG number) {
    Number tempNumber = {0};
    tempNumber.number = number;

    RtlDeleteElementGenericTableAvl(
        &ULLSet->avlTable,
        &tempNumber
    );
}

static inline VOID ULLSetClear(ULLSet* ULLSet) {
    while (RtlNumberGenericTableElementsAvl(&ULLSet->avlTable) > 0) {
        PVOID pElement = RtlGetElementGenericTableAvl(&ULLSet->avlTable, 0);
        RtlDeleteElementGenericTableAvl(&ULLSet->avlTable, pElement);
    }
}

static inline BOOLEAN ULLSetIsEmpty(ULLSet* ULLSet) {
    return (RtlNumberGenericTableElementsAvl(&ULLSet->avlTable) == 0);
}

static inline ULONGLONG ULLGetFirst(ULLSet* ULLSet) {
    PVOID pElement = RtlGetElementGenericTableAvl(&ULLSet->avlTable, 0);
    if (pElement) {
        Number* pNumber = (Number*)pElement;
        return pNumber->number;
    }
    return 0;
}

#endif // DRI_STRING_SET_H