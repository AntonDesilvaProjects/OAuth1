package com.oauth1;

public class Param implements Comparable<Param> {
    private String name;
    private Object value;

    public Param(String name, Object value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }


    @Override
    public int compareTo(Param o) {
        // first compare the name
        int nameComparison = this.getName().compareTo(o.getName());
        // then value
        return nameComparison == 0 ? this.getValue().toString().compareTo(o.getValue().toString()) : nameComparison;
    }
}
