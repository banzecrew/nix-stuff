{ 
  stdenv, 
  fetchurl,
  pkgs ? <nixpkgs>,
  lib
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

  outputs = [  "bin" ];
  phases = [ "unpackPhase" "installPhase" ];

  inputs = "";
  

  installPhase = ''
    cp -rva . $out
    tar -zxf $out/fly-assets/fly-${platform}.tgz -C $out/bin

    for item in `ls ./bin/` ; do
      patchelf --set-interpreter $(cat ${stdenv.cc}/nix-support/dynamic-linker) $out/bin/$item
      ln -s $out/bin/$item 
    done
    export PATH=$out/bin:$PATH
  '';

    postInstall = ''
      
    '';


  meta = with stdenv.lib; {
    description = "Concourse is a pipeline-based continuous thing-doer.";
    homepage = "https://concourse-ci.org/";
    maintainers = [];
    license = "Apache 2.0";
    platforms = platforms.linux;
  };
}
