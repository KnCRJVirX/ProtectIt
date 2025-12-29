#ifndef DRI_STRING_SET_H
#define DRI_STRING_SET_H

#ifndef _AMD64_
#define _AMD64_
#endif

#include <ntifs.h>

#define ELEMOF(s) (sizeof(s) / sizeof(s[0]))

typedef struct StaticString {
    size_t length;
    WCHAR data[64];
} StaticString;

typedef struct StringSet {
    RTL_AVL_TABLE avlTable;
} StringSet;

static inline RTL_GENERIC_COMPARE_RESULTS StaticStringCompare(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
)
{
    StaticString* p1 = (StaticString*)FirstStruct;
    StaticString* p2 = (StaticString*)SecondStruct;

    UNICODE_STRING us1 = {0}, us2 = {0};
    RtlInitUnicodeString(&us1, p1->data);
    RtlInitUnicodeString(&us2, p2->data);

    if (RtlCompareUnicodeString(&us1, &us2, TRUE) == 0) {
        return GenericEqual;
    } else if (RtlCompareUnicodeString(&us1, &us2, TRUE) > 0) {
        return GenericGreaterThan;
    }

    return GenericLessThan;
}

static inline PVOID StaticStringAllocate(
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

static inline VOID StaticStringFree(
    _In_ struct _RTL_AVL_TABLE *Table,
    _In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Buffer
)
{
    ExFreePoolWithTag(Buffer, 'SStr');
}

static inline VOID StringSetInit(StringSet* stringSet) {
    RtlInitializeGenericTableAvl(
        &stringSet->avlTable,
        StaticStringCompare,
        StaticStringAllocate,
        StaticStringFree,
        NULL
    );
}

static inline BOOLEAN StringSetInsert(StringSet* stringSet, PWCHAR str) {
    StaticString tempString = {0};
    size_t strLength = (wcsnlen_s(str, ELEMOF(tempString.data)) + 1) * sizeof(WCHAR);
    tempString.length = strLength;
    RtlCopyMemory(tempString.data, str, min(strLength, sizeof(tempString.data)));
    tempString.data[ELEMOF(tempString.data) - 1] = L'\0';

    BOOLEAN isNew;
    PVOID pInserted = RtlInsertElementGenericTableAvl(
        &stringSet->avlTable,
        &tempString,
        sizeof(StaticString),
        &isNew
    );

    return isNew;
}

static inline BOOLEAN StringSetContains(StringSet* stringSet, PWCHAR str) {
    StaticString tempString = {0};
    size_t strLength = (wcsnlen_s(str, ELEMOF(tempString.data)) + 1) * sizeof(WCHAR);
    tempString.length = strLength;
    RtlCopyMemory(tempString.data, str, min(strLength, sizeof(tempString.data)));
    tempString.data[ELEMOF(tempString.data) - 1] = L'\0';

    PVOID pFound = RtlLookupElementGenericTableAvl(
        &stringSet->avlTable,
        &tempString
    );

    return (pFound != NULL);
}

static inline VOID StringSetRemove(StringSet* stringSet, PWCHAR str) {
    StaticString tempString = {0};
    size_t strLength = (wcsnlen_s(str, ELEMOF(tempString.data)) + 1) * sizeof(WCHAR);
    tempString.length = strLength;
    RtlCopyMemory(tempString.data, str, min(strLength, sizeof(tempString.data)));
    tempString.data[ELEMOF(tempString.data) - 1] = L'\0';

    RtlDeleteElementGenericTableAvl(
        &stringSet->avlTable,
        &tempString
    );
}

static inline VOID StringSetClear(StringSet* stringSet) {
    while (RtlNumberGenericTableElementsAvl(&stringSet->avlTable) > 0) {
        PVOID pElement = RtlGetElementGenericTableAvl(&stringSet->avlTable, 0);
        RtlDeleteElementGenericTableAvl(&stringSet->avlTable, pElement);
    }
}

#endif // DRI_STRING_SET_H