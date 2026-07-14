fn main() {
    println!("cargo:rerun-if-changed=asm/access.S");
    println!("cargo:rerun-if-changed=asm/lower_el.S");
    println!("cargo:rerun-if-changed=asm/vectors.S");
}
