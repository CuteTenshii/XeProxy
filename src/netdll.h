// netdll.h: prototypes for the xam.xex NetDll_* exports. Each takes an
// XNCALLER_TYPE first (xnet.lib hides it from title code); the rest matches the SDK ABI.

#ifndef XEP_NETDLL_H
#define XEP_NETDLL_H

#include "xep.h"

typedef SOCKET (*PFN_socket)(DWORD caller, int af, int type, int proto);
typedef int    (*PFN_closesocket)(DWORD caller, SOCKET s);
typedef int    (*PFN_setsockopt)(DWORD caller, SOCKET s, int level, int optname,
                                 const char *optval, int optlen);
typedef int    (*PFN_bind)(DWORD caller, SOCKET s, const SOCKADDR *name, int namelen);
typedef int    (*PFN_connect)(DWORD caller, SOCKET s, const SOCKADDR *name, int namelen);
typedef int    (*PFN_select)(DWORD caller, int nfds, void *rd, void *wr, void *ex, const void *tv);
typedef int    (*PFN_recv)(DWORD caller, SOCKET s, char *buf, int len, int flags);
typedef int    (*PFN_recvfrom)(DWORD caller, SOCKET s, char *buf, int len, int flags,
                               SOCKADDR *from, int *fromlen);
typedef int    (*PFN_WSARecvFrom)(DWORD caller, SOCKET s, WSABUF *bufs, DWORD cbufs,
                                  DWORD *recvd, DWORD *flags, SOCKADDR *from, int *fromlen,
                                  void *ov, void *cr);
typedef int    (*PFN_send)(DWORD caller, SOCKET s, const char *buf, int len, int flags);
typedef int    (*PFN_sendto)(DWORD caller, SOCKET s, const char *buf, int len, int flags,
                             const SOCKADDR *to, int tolen);
typedef int    (*PFN_WSASendTo)(DWORD caller, SOCKET s, WSABUF *bufs, DWORD cbufs,
                                DWORD *sent, DWORD flags, const SOCKADDR *to, int tolen,
                                void *ov, void *cr);
typedef int    (*PFN_WSAGetLastError)(DWORD caller);
typedef int    (*PFN_WSASetEvent)(DWORD caller, HANDLE hEvent);

typedef int    (*PFN_XNetStartup)(DWORD caller, const XNetStartupParams *p);
typedef int    (*PFN_XNetXnAddrToInAddr)(DWORD caller, const XNADDR *pxna,
                                         const XNKID *pxnkid, IN_ADDR *pina);
typedef int    (*PFN_XNetServerToInAddr)(DWORD caller, IN_ADDR inaServer,
                                         DWORD dwServiceId, IN_ADDR *pina);
typedef int    (*PFN_XNetInAddrToXnAddr)(DWORD caller, IN_ADDR ina, XNADDR *pxna, XNKID *pxnkid);
typedef int    (*PFN_XNetInAddrToServer)(DWORD caller, IN_ADDR ina, IN_ADDR *pinaServer);
typedef DWORD  (*PFN_XNetGetConnectStatus)(DWORD caller, IN_ADDR ina);
typedef int    (*PFN_XNetDnsLookup)(DWORD caller, const char *host, HANDLE hEvent, XNDNS **ppDns);
typedef int    (*PFN_XNetDnsRelease)(DWORD caller, XNDNS *pDns);
// 12 arguments after the caller, in this order, per winsockx.h.
typedef int    (*PFN_XNetQosLookup)(DWORD caller, UINT cxna, const XNADDR **apxna,
                                    const XNKID **apxnkid, const XNKEY **apxnkey,
                                    UINT cina, const IN_ADDR *aina, const DWORD *adwServiceId,
                                    UINT cProbes, DWORD dwBitsPerSec, DWORD dwFlags,
                                    HANDLE hEvent, XNQOS **ppxnqos);
typedef int    (*PFN_XNetQosServiceLookup)(DWORD caller, DWORD dwFlags, HANDLE hEvent,
                                           XNQOS **ppxnqos);
typedef DWORD  (*PFN_XNetGetTitleXnAddr)(DWORD caller, XNADDR *pAddr);
typedef BOOL   (*PFN_XHttpSetOption)(DWORD caller, void *hInternet, DWORD option,
                                     const void *buf, DWORD len);
typedef void  *(*PFN_XHttpConnect)(DWORD caller, void *hSession, const char *server,
                                   WORD port, DWORD reserved);

#endif // XEP_NETDLL_H
