#
# spec file for VMware_GuestSDK 
#
%global buildnum 4449150 

Name:           VMware_GuestSDK
Summary:        VMware GuestSDK
License:        BSD, MIT
Group:          System Environment/Daemons
Version:        10.1.0
Release: 	1%{?dist}
Url:            http://www.vmware.com
Source0:       %{name}_%{version}_%{buildnum}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  make

ExclusiveArch: i686 x86_64

%description

This package contains VMware GuestSDK repackaged into rpms 

%package -n libappmonitorlib
Summary:	Library to access vmware application monitoring api

%description -n libappmonitorlib
This package contains the library for accessing the vmware application monitoring api

%package -n libappmonitorlib-devel
Summary:	Header files for using vmware application monitoring api
Requires:	libappmonitorlib

%description -n libappmonitorlib-devel
This package contains the header files for vmware application monitoring api


%define debug_package %{nil}

%if %{_arch}==i686
%define binarchdir bin32
%define libarchdir lib32
%else 
%if %{_arch}==x86_64
%define binarchdir bin64
%define libarchdir lib64
%else
%error unsupported architecture %{_arch}
%endif
%endif
 
%prep
%setup -q -n GuestSDK 
sed -i docs/VMGuestAppMonitor/samples/C/makefile -e "s/lib32/%{libarchdir}/"

%build
make -C docs/VMGuestAppMonitor/samples/C

%install
install -D -m 0755 bin/%{binarchdir}/vmware-appmonitor $RPM_BUILD_ROOT/%{_bindir}/vmware-appmonitor
install -D -m 0755 docs/VMGuestAppMonitor/samples/C/sample $RPM_BUILD_ROOT/%{_bindir}/vmware-appmonitor-sample
install -D -m 0755 lib/%{libarchdir}/libappmonitorlib.so $RPM_BUILD_ROOT/%{_libdir}/libappmonitorlib.so.%{version}
ln -s libappmonitorlib.so.%{version} $RPM_BUILD_ROOT/%{_libdir}/libappmonitorlib.so
mkdir -p $RPM_BUILD_ROOT/%{_includedir}
install -D -m 0644 include/vmGuestAppMonitorLib.h $RPM_BUILD_ROOT/%{_includedir}/vmGuestLib/vmGuestAppMonitorLib.h
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/pkgconfig
cat <<__EOT__ > $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/libappmonitorlib.pc
prefix=%{_prefix}
exec_prefix=%{_exec_prefix}
libdir=%{_libdir}
includedir=%{_includedir}/vmGuestLib

Name: libappmonitorlib
Description: Library to access VMware ApplicationMonitor-API 
Version: %{version} 
Libs: -L\${libdir} -lappmonitorlib
Cflags: -I\${includedir}
__EOT__

%files
%defattr(-,root,root)
%{_bindir}/vmware-appmonitor-sample

%files -n libappmonitorlib
%defattr(-,root,root)
%{_bindir}/vmware-appmonitor
%{_libdir}/libappmonitorlib.so
%{_libdir}/libappmonitorlib.so.%{version}

%files -n libappmonitorlib-devel
%defattr(-,root,root)
%{_includedir}/vmGuestLib
%{_libdir}/pkgconfig/libappmonitorlib.pc

%changelog
* Fri Nov 24 2017 <klaus.wenninger@aon.at> - 10.1.0_4449150-1
- initial creation 
