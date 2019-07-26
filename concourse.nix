{ 
  stdenv, 
  fetchurl,
  pkgs,
  lib,
  mode ? "web"
}:


with pkgs;


stdenv.mkDerivation rec {
  name = "concourse-${version}";
  platform = "linux-amd64";
  version = "5.3.0";

  src = fetchurl { 
    url = "https://github.com/concourse/concourse/releases/download/v${version}/${name}-${platform}.tgz";
    sha256 = "6fef8fb5d566854560c8a8c141103ea8af4a627c8d8de3ddd68dd3dd3b02ec45"; 
  };
  
  phases = [ "unpackPhase" "installPhase" ];

  inputs = [ (if "${mode}" == "web" then postgresql else "") ];
  
  installPhase = ''
    ${coreutils}/bin/cp -rva . $out
    ${gnutar}/bin/tar -zxf $out/fly-assets/fly-${platform}.tgz -C $out/bin

    for item in `${coreutils}/bin/ls ./bin/` ; do
      ${patchelf}/bin/patchelf --set-interpreter $(${coreutils}/bin/cat ${stdenv.cc}/nix-support/dynamic-linker) $out/bin/$item
    done
    
    ${gnutar}/bin/mkdir -p /var
  '';

  meta = with stdenv.lib; {
    description = "Concourse is a pipeline-based continuous thing-doer.";
    homepage = "https://concourse-ci.org/";
    maintainers = [];
    license = "Apache 2.0";
    platforms = platforms.linux;
  };
}
